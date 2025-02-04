/*
 * Copyright (C) 2008-2012 Red Hat, Inc.
 * Copyright (C) 2015 Tangent Space <jstpierre@mecheye.net>
 * Copyright (C) 2019 Wu Xiaotian <yetist@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include <pthread.h>

#include "polkitbackendcommon.h"

#include "duktape.h"

/* Built source and not too big to worry about deduplication */
#include "initjs.h" /* init.js */

/**
 * SECTION:polkitbackendjsauthority
 * @title: PolkitBackendJsAuthority
 * @short_description: JS Authority
 * @stability: Unstable
 *
 * An (Duktape-based) implementation of #PolkitBackendAuthority that reads and
 * evaluates Javascript files and supports interaction with authentication
 * agents (virtue of being based on #PolkitBackendInteractiveAuthority).
 */

/* ---------------------------------------------------------------------------------------------------- */

struct _PolkitBackendJsAuthorityPrivate
{
  gchar **rules_dirs;
  GFileMonitor **dir_monitors; /* NULL-terminated array of GFileMonitor instances */

  duk_context *cx;

  pthread_t runaway_killer_thread;
};

enum
{
  RUNAWAY_KILLER_THREAD_EXIT_STATUS_UNSET,
  RUNAWAY_KILLER_THREAD_EXIT_STATUS_SUCCESS,
  RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE,
};

static gboolean execute_script_with_runaway_killer(PolkitBackendJsAuthority *authority,
                                                   const gchar *filename);

/* ---------------------------------------------------------------------------------------------------- */

G_DEFINE_TYPE_WITH_PRIVATE (PolkitBackendJsAuthority, polkit_backend_js_authority, POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY);

/* ---------------------------------------------------------------------------------------------------- */

static duk_ret_t js_polkit_log (duk_context *cx);
static duk_ret_t js_polkit_spawn (duk_context *cx);
static duk_ret_t js_polkit_user_is_in_netgroup (duk_context *cx);

static const duk_function_list_entry js_polkit_functions[] =
{
  { "log", js_polkit_log, 1 },
  { "spawn", js_polkit_spawn, 1 },
  { "_userIsInNetGroup", js_polkit_user_is_in_netgroup, 2 },
  { NULL, NULL, 0 },
};

static void report_error (void     *udata,
                          const char *msg)
{
    PolkitBackendJsAuthority *authority = udata;
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "fatal Duktape JS backend error: %s",
                                  (msg ? msg : "no message"));
}

static void
polkit_backend_js_authority_init (PolkitBackendJsAuthority *authority)
{
  authority->priv = polkit_backend_js_authority_get_instance_private (authority);
}

static void
load_scripts (PolkitBackendJsAuthority  *authority)
{
  GList *files = NULL;
  GList *l;
  guint num_scripts = 0;
  GError *error = NULL;
  guint n;

  files = NULL;

  for (n = 0; authority->priv->rules_dirs != NULL && authority->priv->rules_dirs[n] != NULL; n++)
    {
      const gchar *dir_name = authority->priv->rules_dirs[n];
      GDir *dir = NULL;

      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_NOTICE,
                                    "Loading rules from directory %s",
                                    dir_name);

      dir = g_dir_open (dir_name,
                        0,
                        &error);
      if (dir != NULL)
        {
          const gchar *name;
          while ((name = g_dir_read_name (dir)) != NULL)
            {
              if (g_str_has_suffix (name, ".rules"))
                files = g_list_prepend (files, g_strdup_printf ("%s/%s", dir_name, name));
            }
          g_dir_close (dir);
        }
      else
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        LOG_LEVEL_NOTICE,
                                        "Error opening rules directory: %s (%s, %d)",
                                        error->message, g_quark_to_string (error->domain), error->code);
          g_clear_error (&error);
        }
    }

  files = g_list_sort (files, (GCompareFunc) polkit_backend_common_rules_file_name_cmp);

  for (l = files; l != NULL; l = l->next)
    {
      const gchar *filename = (gchar *)l->data;

      if (!execute_script_with_runaway_killer(authority, filename))
          continue;
      num_scripts++;
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                      LOG_LEVEL_DEBUG,
                                      "Loaded and executed script in file %s",
                                      filename);
    }

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                LOG_LEVEL_NOTICE,
                                "Finished loading, compiling and executing %d rules",
                                num_scripts);
  g_list_free_full (files, g_free);
}

void
polkit_backend_common_reload_scripts (PolkitBackendJsAuthority *authority)
{
  duk_context *cx = authority->priv->cx;

  duk_set_top (cx, 0);
  if (!duk_get_global_string (cx, "polkit")) {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error deleting old rules, not loading new ones");
      return;
  }
  duk_push_string (cx, "_deleteRules");

  duk_call_prop (cx, 0, 0);

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                LOG_LEVEL_NOTICE,
                                "Collecting garbage unconditionally...");

  load_scripts (authority);

  /* Let applications know we have new rules... */
  g_signal_emit_by_name (authority, "changed");
}

static void
setup_file_monitors (PolkitBackendJsAuthority *authority)
{
  guint n;
  GPtrArray *p;

  p = g_ptr_array_new ();
  for (n = 0; authority->priv->rules_dirs != NULL && authority->priv->rules_dirs[n] != NULL; n++)
    {
      GFile *file;
      GError *error;
      GFileMonitor *monitor;

      file = g_file_new_for_path (authority->priv->rules_dirs[n]);
      error = NULL;
      monitor = g_file_monitor_directory (file,
                                          G_FILE_MONITOR_NONE,
                                          NULL,
                                          &error);
      g_object_unref (file);
      if (monitor == NULL)
        {
          g_warning ("Error monitoring directory %s: %s",
                     authority->priv->rules_dirs[n],
                     error->message);
          g_clear_error (&error);
        }
      else
        {
          g_signal_connect (monitor,
                            "changed",
                            G_CALLBACK (polkit_backend_common_on_dir_monitor_changed),
                            authority);
          g_ptr_array_add (p, monitor);
        }
    }
  g_ptr_array_add (p, NULL);
  authority->priv->dir_monitors = (GFileMonitor**) g_ptr_array_free (p, FALSE);
}

void
polkit_backend_common_js_authority_constructed (GObject *object)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (object);
  duk_context *cx;

  cx = duk_create_heap (NULL, NULL, NULL, authority, report_error);
  if (cx == NULL)
    goto fail;

  authority->priv->cx = cx;

  duk_push_global_object (cx);
  duk_push_object (cx);
  duk_put_function_list (cx, -1, js_polkit_functions);
  duk_put_prop_string (cx, -2, "polkit");

  /* load polkit objects/functions into JS context (e.g. addRule(),
   * _deleteRules(), _runRules() et al)
   */
  duk_eval_string (cx, init_js);

  if (authority->priv->rules_dirs == NULL)
    {
      authority->priv->rules_dirs = g_new0 (gchar *, 5);
      authority->priv->rules_dirs[0] = g_strdup (PACKAGE_SYSCONF_DIR "/polkit-1/rules.d");
      authority->priv->rules_dirs[1] = g_strdup ("/run/polkit-1/rules.d");
      authority->priv->rules_dirs[2] = g_strdup ("/usr/local/share/polkit-1/rules.d");
      authority->priv->rules_dirs[3] = g_strdup (PACKAGE_DATA_DIR "/polkit-1/rules.d");
    }

  setup_file_monitors (authority);
  load_scripts (authority);

  G_OBJECT_CLASS (polkit_backend_js_authority_parent_class)->constructed (object);
  return;

 fail:
  g_critical ("Error initializing JavaScript environment");
  g_assert_not_reached ();
}

void
polkit_backend_common_js_authority_finalize (GObject *object)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (object);
  guint n;

  for (n = 0; authority->priv->dir_monitors != NULL && authority->priv->dir_monitors[n] != NULL; n++)
    {
      GFileMonitor *monitor = authority->priv->dir_monitors[n];
      g_signal_handlers_disconnect_by_func (monitor,
                                            G_CALLBACK (polkit_backend_common_on_dir_monitor_changed),
                                            authority);
      g_object_unref (monitor);
    }
  g_free (authority->priv->dir_monitors);
  g_strfreev (authority->priv->rules_dirs);

  duk_destroy_heap (authority->priv->cx);

  G_OBJECT_CLASS (polkit_backend_js_authority_parent_class)->finalize (object);
}

void
polkit_backend_common_js_authority_set_property (GObject      *object,
                                                 guint         property_id,
                                                 const GValue *value,
                                                 GParamSpec   *pspec)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (object);

  switch (property_id)
    {
      case PROP_RULES_DIRS:
        g_assert (authority->priv->rules_dirs == NULL);
        authority->priv->rules_dirs = (gchar **) g_value_dup_boxed (value);
        break;

      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
polkit_backend_js_authority_class_init (PolkitBackendJsAuthorityClass *klass)
{
  polkit_backend_common_js_authority_class_init_common (klass);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
set_property_str (duk_context *cx,
                  const gchar *name,
                  const gchar *value)
{
  duk_push_string (cx, value);
  duk_put_prop_string (cx, -2, name);
}

static void
set_property_strv (duk_context *cx,
                   const gchar *name,
                   GPtrArray   *value)
{
  guint n;
  duk_push_array (cx);
  for (n = 0; n < value->len; n++)
    {
      duk_push_string (cx, g_ptr_array_index (value, n));
      duk_put_prop_index (cx, -2, n);
    }
  duk_put_prop_string (cx, -2, name);
}

static void
set_property_int32 (duk_context *cx,
                    const gchar *name,
                    gint32       value)
{
  duk_push_int (cx, value);
  duk_put_prop_string (cx, -2, name);
}

static void
set_property_bool (duk_context *cx,
                   const char  *name,
                   gboolean     value)
{
  duk_push_boolean (cx, value);
  duk_put_prop_string (cx, -2, name);
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
push_subject (duk_context               *cx,
              PolkitSubject             *subject,
              PolkitIdentity            *user_for_subject,
              gboolean                   subject_is_local,
              gboolean                   subject_is_active,
              GError                   **error)
{
  gboolean ret = FALSE;
  gboolean no_new_privs = FALSE;
  gint pidfd = -1;
  pid_t pid_early, pid_late;
  uid_t uid;
  PolkitSubject *process = NULL;
  gchar *user_name = NULL;
  GPtrArray *groups = NULL;
  GArray *gids_from_dbus = NULL;
  struct passwd *passwd;
  char *seat_str = NULL;
  char *session_str = NULL;
  char *system_unit = NULL;

  if (!duk_get_global_string (cx, "Subject")) {
    return FALSE;
  }

  duk_new (cx, 0);

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      process = subject;
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, error);
      if (process == NULL)
        goto out;
    }
  else
    {
      g_assert_not_reached ();
    }

  pid_early = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));
  pidfd = polkit_unix_process_get_pidfd (POLKIT_UNIX_PROCESS (process));

#ifdef HAVE_LIBSYSTEMD
#if HAVE_SD_PIDFD_GET_SESSION
  if (pidfd >= 0)
    sd_pidfd_get_session (pidfd, &session_str);
  else
#endif /* HAVE_SD_PIDFD_GET_SESSION */
    sd_pid_get_session (pid_early, &session_str);
  if (session_str)
    sd_session_get_seat (session_str, &seat_str);
#endif /* HAVE_LIBSYSTEMD */

  g_assert (POLKIT_IS_UNIX_USER (user_for_subject));
  uid = polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_for_subject));

  groups = g_ptr_array_new_with_free_func (g_free);
  gids_from_dbus = polkit_unix_process_get_gids (POLKIT_UNIX_PROCESS (process));

passwd = getpwuid (uid);
if (passwd == NULL)
  {
    user_name = g_strdup_printf ("%d", (gint) uid);
    g_warning ("Error looking up info for uid %d: %m", (gint) uid);
  }
else
  {
    user_name = g_strdup (passwd->pw_name);
  }

  /* D-Bus will give us supplementary groups too, so prefer that to looking up
   * the group from the uid. */
  if (gids_from_dbus && gids_from_dbus->len > 0)
    {
      gint n;
      for (n = 0; n < gids_from_dbus->len; n++)
        {
          struct group *group;
          group = getgrgid (g_array_index (gids_from_dbus, gid_t, n));
          if (group == NULL)
            {
              g_ptr_array_add (groups, g_strdup_printf ("%d", (gint) g_array_index (gids_from_dbus, gid_t, n)));
            }
          else
            {
              g_ptr_array_add (groups, g_strdup (group->gr_name));
            }
        }
    }
  else
    {
      if (passwd != NULL)
        {
          gid_t gids[512];
          int num_gids = 512;

          if (getgrouplist (passwd->pw_name,
                            passwd->pw_gid,
                            gids,
                            &num_gids) < 0)
            {
              g_warning ("Error looking up groups for uid %d: %m", (gint) uid);
            }
          else
            {
              gint n;
              for (n = 0; n < num_gids; n++)
                {
                  struct group *group;
                  group = getgrgid (gids[n]);
                  if (group == NULL)
                    {
                      g_ptr_array_add (groups, g_strdup_printf ("%d", (gint) gids[n]));
                    }
                  else
                    {
                      g_ptr_array_add (groups, g_strdup (group->gr_name));
                    }
                }
            }
        }
    }

  /* Query the unit, will work only if we got the pidfd from dbus-daemon/broker.
   * Best-effort operation, will log on failure, but we don't bail here. But
   * only do so if the pidfd was marked as safe, i.e.: we got it from D-Bus so
   * it can be trusted end-to-end, with no reuse attack window.  */
  if (polkit_unix_process_get_pidfd_is_safe (POLKIT_UNIX_PROCESS (process)))
    polkit_backend_common_pidfd_to_systemd_unit (pidfd, &system_unit, &no_new_privs);

  /* In case we are using PIDFDs, check that the PID still matches to avoid race
   * conditions and PID recycle attacks.
   */
  pid_late = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));
  if (pid_late != pid_early)
    {
      if (pid_late <= 0)
        {
          g_warning ("Process %d terminated", (gint) pid_early);
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Process %d terminated", (gint) pid_early);
        }
      else
      {
        g_warning ("Process changed pid from %d to %d", (gint) pid_early, (gint) pid_late);
        g_set_error (error,
                     POLKIT_ERROR,
                     POLKIT_ERROR_FAILED,
                     "Process changed pid from %d to %d", (gint) pid_early, (gint) pid_late);
      }
      goto out;
    }

  set_property_int32 (cx, "pid", pid_early);
  set_property_str (cx, "user", user_name);
  set_property_strv (cx, "groups", groups);
  set_property_str (cx, "seat", seat_str);
  set_property_str (cx, "session", session_str);
  set_property_str (cx, "system_unit", system_unit);
  /* If we have a unit, also record if it has the NoNewPrivileges setting enabled */
  if (system_unit)
    set_property_bool (cx, "no_new_privileges", no_new_privs);
  set_property_bool (cx, "local", subject_is_local);
  set_property_bool (cx, "active", subject_is_active);

  ret = TRUE;

 out:
  if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    g_object_unref (process);
  free (session_str);
  free (seat_str);
  free (system_unit);
  g_free (user_name);
  if (groups != NULL)
    g_ptr_array_unref (groups);
  if (gids_from_dbus != NULL)
    g_array_unref (gids_from_dbus);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
push_action_and_details (duk_context               *cx,
                         const gchar               *action_id,
                         PolkitDetails             *details)
{
  gchar **keys;
  guint n;

  if (!duk_get_global_string (cx, "Action")) {
    return FALSE;
  }

  duk_new (cx, 0);

  set_property_str (cx, "id", action_id);

  keys = polkit_details_get_keys (details);
  for (n = 0; keys != NULL && keys[n] != NULL; n++)
    {
      gchar *key;
      const gchar *value;
      key = g_strdup_printf ("_detail_%s", keys[n]);
      value = polkit_details_lookup (details, keys[n]);
      set_property_str (cx, key, value);
      g_free (key);
    }
  g_strfreev (keys);

  return TRUE;
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct {
  PolkitBackendJsAuthority *authority;
  const gchar *filename;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
  gint ret;
} RunawayKillerCtx;

static gpointer
runaway_killer_thread_execute_js (gpointer user_data)
{
  RunawayKillerCtx *ctx = user_data;
  duk_context *cx = ctx->authority->priv->cx;

  int oldtype, pthread_err;

  if ((pthread_err = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error setting thread cancel type: %s",
                                  strerror(pthread_err));
    goto err;
  }

  GFile *file = g_file_new_for_path(ctx->filename);
  char *contents;
  gsize len;

  if (!g_file_load_contents(file, NULL, &contents, &len, NULL, NULL)) {
    polkit_backend_authority_log(POLKIT_BACKEND_AUTHORITY(ctx->authority),
                                 LOG_LEVEL_ERROR,
                                 "Error loading script %s", ctx->filename);
    g_object_unref(file);
    goto err;
  }

  g_object_unref(file);

  /* evaluate the script, trying to print context in any syntax errors
     found */
  if (duk_peval_lstring(cx, contents, len) != 0)
  {
    polkit_backend_authority_log(POLKIT_BACKEND_AUTHORITY(ctx->authority),
                                 LOG_LEVEL_ERROR,
                                 "Error compiling script %s: %s", ctx->filename,
                                 duk_safe_to_string(cx, -1));
    duk_pop(cx);
    goto free_err;
  }
  g_free(contents);

  if ((pthread_err = pthread_mutex_lock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error locking mutex: %s",
                                  strerror(pthread_err));
    return NULL;
  }

  ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_SUCCESS;
  goto end;

free_err:
  g_free(contents);
err:
  if ((pthread_err = pthread_mutex_lock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error locking mutex: %s",
                                  strerror(pthread_err));
    return NULL;
  }
  ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE;
end:
  if ((pthread_err = pthread_cond_signal(&ctx->cond))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error signaling on condition variable: %s",
                                  strerror(pthread_err));
    ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE;
  }
  if ((pthread_err = pthread_mutex_unlock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error unlocking mutex: %s",
                                  strerror(pthread_err));
    ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE;
  }
  return NULL;
}

static gpointer
runaway_killer_thread_call_js (gpointer user_data)
{
  RunawayKillerCtx *ctx = user_data;
  duk_context *cx = ctx->authority->priv->cx;
  int oldtype, pthread_err;

  if ((pthread_err = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error setting thread cancel type: %s",
                                  strerror(pthread_err));
    goto err;
  }

  if (duk_pcall_prop (cx, 0, 2) != DUK_EXEC_SUCCESS)
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                    LOG_LEVEL_ERROR,
                                    "Error evaluating admin rules: %s",
                                    duk_safe_to_string (cx, -1));
      goto err;
    }

  if ((pthread_err = pthread_mutex_lock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error locking mutex: %s",
                                  strerror(pthread_err));
    return NULL;
  }

  ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_SUCCESS;
  goto end;

err:
  if ((pthread_err = pthread_mutex_lock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error locking mutex: %s",
                                  strerror(pthread_err));
    return NULL;
  }
  ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE;
end:
  if ((pthread_err = pthread_cond_signal(&ctx->cond))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error signaling on condition variable: %s",
                                  strerror(pthread_err));
    ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE;
  }
  if ((pthread_err = pthread_mutex_unlock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (ctx->authority),
                                  LOG_LEVEL_ERROR,
                                  "Error unlocking mutex: %s",
                                  strerror(pthread_err));
    ctx->ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE;
  }

  return NULL;
}

#if defined (HAVE_PTHREAD_CONDATTR_SETCLOCK)
#  if defined(CLOCK_MONOTONIC)
#    define PK_CLOCK CLOCK_MONOTONIC
#  elif defined(CLOCK_BOOTTIME)
#    define PK_CLOCK CLOCK_BOOTTIME
#  else
     /* No suitable clock */
#    undef HAVE_PTHREAD_CONDATTR_SETCLOCK
#    define PK_CLOCK CLOCK_REALTIME
#  endif
#else  /* ! HAVE_PTHREAD_CONDATTR_SETCLOCK */
#  define PK_CLOCK CLOCK_REALTIME
#endif /* ! HAVE_PTHREAD_CONDATTR_SETCLOCK */

static gboolean
runaway_killer_common(PolkitBackendJsAuthority *authority, RunawayKillerCtx *ctx, void *js_context_cb (void *user_data))
{
  int pthread_err;
  gboolean cancel = FALSE;
#ifdef HAVE_PTHREAD_CONDATTR_SETCLOCK
  pthread_condattr_t attr;
#endif
  struct timespec abs_time;

#ifdef HAVE_PTHREAD_CONDATTR_SETCLOCK
  if ((pthread_err = pthread_condattr_init(&attr))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error initializing condition variable attributes: %s",
                                  strerror(pthread_err));
    return FALSE;
  }
  if ((pthread_err = pthread_condattr_setclock(&attr, PK_CLOCK))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error setting condition variable attributes: %s",
                                  strerror(pthread_err));
    goto err_clean_condattr;
  }
  /* Init again, with needed attr */
  if ((pthread_err = pthread_cond_init(&ctx->cond, &attr))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error initializing condition variable: %s",
                                  strerror(pthread_err));
    goto err_clean_condattr;
  }
#endif

  if ((pthread_err = pthread_mutex_lock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error locking mutex: %s",
                                  strerror(pthread_err));
    goto err_clean_cond;
  }

  if (clock_gettime(PK_CLOCK, &abs_time)) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error getting system's monotonic time: %s",
                                  strerror(errno));
    goto err_clean_cond;
  }
  abs_time.tv_sec += RUNAWAY_KILLER_TIMEOUT;

  if ((pthread_err = pthread_create(&authority->priv->runaway_killer_thread, NULL,
                                    js_context_cb, ctx))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error creating runaway JS killer thread: %s",
                                  strerror(pthread_err));
    goto err_clean_cond;
  }

  while (ctx->ret == RUNAWAY_KILLER_THREAD_EXIT_STATUS_UNSET) /* loop to treat spurious wakeups */
    if (pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &abs_time) == ETIMEDOUT) {
      cancel = TRUE;

      /* Log that we are terminating the script */
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_WARNING,
                                    "Terminating runaway script after %d seconds",
                                    RUNAWAY_KILLER_TIMEOUT);

      break;
    }

  if ((pthread_err = pthread_mutex_unlock(&ctx->mutex))) {
    polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                  LOG_LEVEL_ERROR,
                                  "Error unlocking mutex: %s",
                                  strerror(pthread_err));
    goto err_clean_cond;
  }

  if (cancel) {
    if ((pthread_err = pthread_cancel (authority->priv->runaway_killer_thread))) {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error cancelling runaway JS killer thread: %s",
                                    strerror(pthread_err));
      goto err_clean_cond;
    }
  }
  if ((pthread_err = pthread_join (authority->priv->runaway_killer_thread, NULL))) {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error joining runaway JS killer thread: %s",
                                    strerror(pthread_err));
      goto err_clean_cond;
    }

  return ctx->ret == RUNAWAY_KILLER_THREAD_EXIT_STATUS_SUCCESS;

    err_clean_cond:
#ifdef HAVE_PTHREAD_CONDATTR_SETCLOCK
  pthread_cond_destroy(&ctx->cond);
    err_clean_condattr:
  pthread_condattr_destroy(&attr);
#endif
  return FALSE;
}

/* Blocking for at most RUNAWAY_KILLER_TIMEOUT */
static gboolean
execute_script_with_runaway_killer(PolkitBackendJsAuthority *authority,
                                   const gchar *filename)
{
  RunawayKillerCtx ctx = {.authority = authority, .filename = filename,
                          .ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_UNSET,
                          .mutex = PTHREAD_MUTEX_INITIALIZER,
                          .cond = PTHREAD_COND_INITIALIZER};

  return runaway_killer_common(authority, &ctx, &runaway_killer_thread_execute_js);
}

/* Calls already stacked function and args. Blocking for at most
 * RUNAWAY_KILLER_TIMEOUT. If timeout is the case, ctx.ret will be
 * RUNAWAY_KILLER_THREAD_EXIT_STATUS_UNSET, thus returning FALSE.
 */
static gboolean
call_js_function_with_runaway_killer(PolkitBackendJsAuthority *authority)
{
  RunawayKillerCtx ctx = {.authority = authority,
                          .ret = RUNAWAY_KILLER_THREAD_EXIT_STATUS_UNSET,
                          .mutex = PTHREAD_MUTEX_INITIALIZER,
                          .cond = PTHREAD_COND_INITIALIZER};

  return runaway_killer_common(authority, &ctx, &runaway_killer_thread_call_js);
}

/* ---------------------------------------------------------------------------------------------------- */

GList *
polkit_backend_common_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *_authority,
                                                              PolkitSubject                     *caller,
                                                              PolkitSubject                     *subject,
                                                              PolkitIdentity                    *user_for_subject,
                                                              gboolean                           subject_is_local,
                                                              gboolean                           subject_is_active,
                                                              const gchar                       *action_id,
                                                              PolkitDetails                     *details)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (_authority);
  GList *ret = NULL;
  guint n;
  GError *error = NULL;
  const char *ret_str = NULL;
  gchar **ret_strs = NULL;
  duk_context *cx = authority->priv->cx;

  duk_set_top (cx, 0);
  if (!duk_get_global_string (cx, "polkit")) {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error deleting old rules, not loading new ones");
      goto out;
  }

  duk_push_string (cx, "_runAdminRules");

  if (!push_action_and_details (cx, action_id, details))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error converting action and details to JS object");
      goto out;
    }

  if (!push_subject (cx, subject, user_for_subject, subject_is_local, subject_is_active, &error))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error converting subject to JS object: %s",
                                    error->message);
      g_clear_error (&error);
      goto out;
    }

  if (!call_js_function_with_runaway_killer (authority))
    goto out;

  ret_str = duk_require_string (cx, -1);

  ret_strs = g_strsplit (ret_str, ",", -1);
  for (n = 0; ret_strs != NULL && ret_strs[n] != NULL; n++)
    {
      const gchar *identity_str = ret_strs[n];
      PolkitIdentity *identity;

      error = NULL;
      identity = polkit_identity_from_string (identity_str, &error);
      if (identity == NULL)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        LOG_LEVEL_WARNING,
                                        "Identity `%s' is not valid, ignoring: %s",
                                        identity_str, error->message);
          g_clear_error (&error);
        }
      else
        {
          ret = g_list_prepend (ret, identity);
        }
    }
  ret = g_list_reverse (ret);

 out:
  g_strfreev (ret_strs);
  /* fallback to root password auth */
  if (ret == NULL)
    ret = g_list_prepend (ret, polkit_unix_user_new (0));

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

PolkitImplicitAuthorization
polkit_backend_common_js_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *_authority,
                                                             PolkitSubject                     *caller,
                                                             PolkitSubject                     *subject,
                                                             PolkitIdentity                    *user_for_subject,
                                                             gboolean                           subject_is_local,
                                                             gboolean                           subject_is_active,
                                                             const gchar                       *action_id,
                                                             PolkitDetails                     *details,
                                                             PolkitImplicitAuthorization        implicit)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (_authority);
  PolkitImplicitAuthorization ret = implicit;
  GError *error = NULL;
  gchar *ret_str = NULL;
  gboolean good = FALSE;
  duk_context *cx = authority->priv->cx;

  duk_set_top (cx, 0);
  if (!duk_get_global_string (cx, "polkit")) {
      goto out;
  }

  duk_push_string (cx, "_runRules");

  if (!push_action_and_details (cx, action_id, details))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error converting action and details to JS object");
      goto out;
    }

  if (!push_subject (cx, subject, user_for_subject, subject_is_local, subject_is_active, &error))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_ERROR,
                                    "Error converting subject to JS object: %s",
                                    error->message);
      g_clear_error (&error);
      goto out;
    }

  // If any error is the js context happened (ctx.ret ==
  // RUNAWAY_KILLER_THREAD_EXIT_STATUS_FAILURE) or it never properly returned
  // (runaway scripts or ctx.ret == RUNAWAY_KILLER_THREAD_EXIT_STATUS_UNSET),
  // unauthorize
  if (!call_js_function_with_runaway_killer (authority))
    goto out;

  if (duk_is_null(cx, -1)) {
    /* this is fine, means there was no match, use implicit authorizations */
    good = TRUE;
    goto out;
  }
  ret_str = g_strdup (duk_require_string (cx, -1));
  if (!polkit_implicit_authorization_from_string (ret_str, &ret))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    LOG_LEVEL_WARNING,
                                    "Returned result `%s' is not valid",
                                    ret_str);
      goto out;
    }

  good = TRUE;

 out:
  if (!good)
    ret = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
  if (ret_str != NULL)
      g_free (ret_str);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static duk_ret_t
js_polkit_log (duk_context *cx)
{
  const char *str = duk_require_string (cx, 0);
  fprintf (stderr, "%s\n", str);
  return 0;
}

/* ---------------------------------------------------------------------------------------------------- */

static duk_ret_t
js_polkit_spawn (duk_context *cx)
{
  duk_ret_t ret = DUK_RET_ERROR;
  gchar *standard_output = NULL;
  gchar *standard_error = NULL;
  gint exit_status;
  GError *error = NULL;
  guint32 array_len;
  gchar **argv = NULL;
  GMainContext *context = NULL;
  GMainLoop *loop = NULL;
  SpawnData data = {0};
  char *err_str = NULL;
  guint n;

  if (!duk_is_array (cx, 0))
    goto out;

  array_len = duk_get_length (cx, 0);

  argv = g_new0 (gchar*, array_len + 1);
  for (n = 0; n < array_len; n++)
    {
      duk_get_prop_index (cx, 0, n);
      argv[n] = g_strdup (duk_to_string (cx, -1));
      duk_pop (cx);
    }

  context = g_main_context_new ();
  loop = g_main_loop_new (context, FALSE);

  g_main_context_push_thread_default (context);

  data.loop = loop;
  polkit_backend_common_spawn ((const gchar *const *) argv,
                               10, /* timeout_seconds */
                               NULL, /* cancellable */
                               polkit_backend_common_spawn_cb,
                               &data);

  g_main_loop_run (loop);

  g_main_context_pop_thread_default (context);

  if (!polkit_backend_common_spawn_finish (data.res,
                                           &exit_status,
                                           &standard_output,
                                           &standard_error,
                                           &error))
    {
      err_str = g_strdup_printf ("Error spawning helper: %s (%s, %d)",
                                 error->message, g_quark_to_string (error->domain), error->code);
      g_clear_error (&error);
      goto out;
    }

  if (!(WIFEXITED (exit_status) && WEXITSTATUS (exit_status) == 0))
    {
      GString *gstr;
      gstr = g_string_new (NULL);
      if (WIFEXITED (exit_status))
        {
          g_string_append_printf (gstr,
                                  "Helper exited with non-zero exit status %d",
                                  WEXITSTATUS (exit_status));
        }
      else if (WIFSIGNALED (exit_status))
        {
          g_string_append_printf (gstr,
                                  "Helper was signaled with signal %s (%d)",
                                  polkit_backend_common_get_signal_name (WTERMSIG (exit_status)),
                                  WTERMSIG (exit_status));
        }
      g_string_append_printf (gstr, ", stdout=`%s', stderr=`%s'",
                              standard_output, standard_error);
      err_str = g_string_free (gstr, FALSE);
      goto out;
    }

  duk_push_string (cx, standard_output);
  ret = 1;

 out:
  g_strfreev (argv);
  g_free (standard_output);
  g_free (standard_error);
  g_clear_object (&data.res);
  if (loop != NULL)
    g_main_loop_unref (loop);
  if (context != NULL)
    g_main_context_unref (context);

  if (err_str)
    {
      duk_push_error_object (cx, DUK_ERR_ERROR, err_str);
      free (err_str);
      duk_throw (cx);
      g_assert_not_reached ();
    }

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */


static duk_ret_t
js_polkit_user_is_in_netgroup (duk_context *cx)
{
  gboolean is_in_netgroup = FALSE;
#ifdef HAVE_SETNETGRENT
  const char *user;
  const char *netgroup;

  user = duk_require_string (cx, 0);
  netgroup = duk_require_string (cx, 1);
  if (innetgr (netgroup,
               NULL,  /* host */
               user,
               NULL)) /* domain */
    {
      is_in_netgroup = TRUE;
    }
#endif
  duk_push_boolean (cx, is_in_netgroup);
  return 1;
}

/* ---------------------------------------------------------------------------------------------------- */

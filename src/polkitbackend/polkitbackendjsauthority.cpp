/*
 * Copyright (C) 2008-2012 Red Hat, Inc.
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

#include "polkitbackendcommon.h"

#include <js/CompilationAndEvaluation.h>
#include <js/ContextOptions.h>
#include <js/Initialization.h>
#include <js/Realm.h>
#include <js/SourceText.h>
#include <js/Warnings.h>
#include <js/Array.h>
#include <jsapi.h>

/* Built source and not too big to worry about deduplication */
#include "initjs.h" /* init.js */

#ifdef JSGC_USE_EXACT_ROOTING
/* See https://developer.mozilla.org/en-US/docs/SpiderMonkey/Internals/GC/Exact_Stack_Rooting
 * for more information about exact stack rooting.
 */
#error "This code is not safe in SpiderMonkey exact stack rooting configurations"
#endif

/**
 * SECTION:polkitbackendjsauthority
 * @title: PolkitBackendJsAuthority
 * @short_description: JS Authority
 * @stability: Unstable
 *
 * An (SpiderMonkey-based) implementation of #PolkitBackendAuthority that reads
 * and evaluates Javascript files and supports interaction with authentication
 * agents (virtue of being based on #PolkitBackendInteractiveAuthority).
 */

/* ---------------------------------------------------------------------------------------------------- */

static class JsInitHelperType
{
public:
	JsInitHelperType() { JS_Init(); }
	~JsInitHelperType() { JS_ShutDown(); }
} JsInitHelper;

struct _PolkitBackendJsAuthorityPrivate
{
  gchar **rules_dirs;
  GFileMonitor **dir_monitors; /* NULL-terminated array of GFileMonitor instances */

  JSContext *cx;
  JS::Heap<JSObject*> *js_global;
  JSAutoRealm *ac;
  JS::Heap<JSObject*> *js_polkit;

  GThread *runaway_killer_thread;
  GMainContext *rkt_context;
  GMainLoop *rkt_loop;
  GSource *rkt_source;
  GMutex rkt_timeout_pending_mutex;
  gboolean rkt_timeout_pending;

  /* A list of JSObject instances */
  GList *scripts;
};

static bool execute_script_with_runaway_killer (PolkitBackendJsAuthority *authority,
                                    JS::HandleScript                 script,
                                    JS::MutableHandleValue           rval);

/* ---------------------------------------------------------------------------------------------------- */

static gpointer runaway_killer_thread_func (gpointer user_data);
static void runaway_killer_terminate (PolkitBackendJsAuthority *authority);

G_DEFINE_TYPE (PolkitBackendJsAuthority, polkit_backend_js_authority, POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY);

/* ---------------------------------------------------------------------------------------------------- */

static const struct JSClassOps js_global_class_ops = {
  nullptr,  // addProperty
  nullptr,  // deleteProperty
  nullptr,  // enumerate
  nullptr,  // newEnumerate
  nullptr,  // resolve
  nullptr,  // mayResolve
  nullptr,  // finalize
  nullptr,  // call
  nullptr,  // construct
  JS_GlobalObjectTraceHook
};

static JSClass js_global_class = {
  "global",
  JSCLASS_GLOBAL_FLAGS,
  &js_global_class_ops
};

/* ---------------------------------------------------------------------------------------------------- */
static const struct JSClassOps js_polkit_class_ops = {
  nullptr,  // addProperty
  nullptr,  // deleteProperty
  nullptr,  // enumerate
  nullptr,  // newEnumerate
  nullptr,  // resolve
  nullptr,  // mayResolve
  nullptr,  // finalize
  nullptr,  // call
  nullptr,  // construct
  nullptr   // trace
};

static JSClass js_polkit_class = {
  "Polkit",
  0,
  &js_polkit_class_ops
};

static bool js_polkit_log (JSContext *cx, unsigned argc, JS::Value *vp);
static bool js_polkit_spawn (JSContext *cx, unsigned argc, JS::Value *vp);
static bool js_polkit_user_is_in_netgroup (JSContext *cx, unsigned argc, JS::Value *vp);

static JSFunctionSpec js_polkit_functions[] =
{
  JS_FN("log",            js_polkit_log,            0, 0),
  JS_FN("spawn",          js_polkit_spawn,          0, 0),
  JS_FN("_userIsInNetGroup", js_polkit_user_is_in_netgroup,          0, 0),
  JS_FS_END
};

/* ---------------------------------------------------------------------------------------------------- */

static void report_error (JSContext     *cx,
                          JSErrorReport *report)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx));
  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "%s:%u: %s",
                                report->filename ? report->filename : "<no filename>",
                                (unsigned int) report->lineno,
                                report->message().c_str());
}

static void
polkit_backend_js_authority_init (PolkitBackendJsAuthority *authority)
{
  authority->priv = G_TYPE_INSTANCE_GET_PRIVATE (authority,
                                                 POLKIT_BACKEND_TYPE_JS_AUTHORITY,
                                                 PolkitBackendJsAuthorityPrivate);
}

/* authority->priv->cx must be within a request */
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
                                    "Loading rules from directory %s",
                                    dir_name);

      dir = g_dir_open (dir_name,
                        0,
                        &error);
      if (dir == NULL)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error opening rules directory: %s (%s, %d)",
                                        error->message, g_quark_to_string (error->domain), error->code);
          g_clear_error (&error);
        }
      else
        {
          const gchar *name;
          while ((name = g_dir_read_name (dir)) != NULL)
            {
              if (g_str_has_suffix (name, ".rules"))
                files = g_list_prepend (files, g_strdup_printf ("%s/%s", dir_name, name));
            }
          g_dir_close (dir);
        }
    }

  files = g_list_sort (files, (GCompareFunc) polkit_backend_common_rules_file_name_cmp);

  for (l = files; l != NULL; l = l->next)
    {
      const gchar *filename = (gchar *)l->data;
      JS::CompileOptions options(authority->priv->cx);
      JS::RootedScript script(authority->priv->cx,
                              JS::CompileUtf8Path (authority->priv->cx,
                                                   options,
                                                   filename));
      if (!script)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error compiling script %s",
                                        filename);
          continue;
        }

      /* evaluate the script */
      JS::RootedValue rval(authority->priv->cx);
      if (!execute_script_with_runaway_killer (authority,
                                               script,
                                               &rval))
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error executing script %s",
                                        filename);
          continue;
        }

      //g_print ("Successfully loaded and evaluated script `%s'\n", filename);

      num_scripts++;
    }

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Finished loading, compiling and executing %d rules",
                                num_scripts);
  g_list_free_full (files, g_free);
}

void
polkit_backend_common_reload_scripts (PolkitBackendJsAuthority *authority)
{
  JS::RootedValueArray<1> args(authority->priv->cx);
  JS::RootedValue rval(authority->priv->cx);

  JS::RootedObject js_polkit(authority->priv->cx, authority->priv->js_polkit->get ());

  args[0].setUndefined ();
  if (!JS_CallFunctionName(authority->priv->cx,
                           js_polkit,
                           "_deleteRules",
                           args,
                           &rval))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error deleting old rules, not loading new ones");
      return;
    }

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Collecting garbage unconditionally...");
  JS_GC (authority->priv->cx);

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

  authority->priv->cx = JS_NewContext (8L * 1024L * 1024L);
  if (authority->priv->cx == NULL)
    goto fail;

  if (!JS::InitSelfHostedCode (authority->priv->cx))
    goto fail;

  JS::SetWarningReporter(authority->priv->cx, report_error);
  JS_SetContextPrivate (authority->priv->cx, authority);


  {
    JS::RealmOptions compart_opts;

    JS::RootedObject global(authority->priv->cx);

    authority->priv->js_global = new JS::Heap<JSObject*> (JS_NewGlobalObject (authority->priv->cx, &js_global_class, NULL, JS::FireOnNewGlobalHook, compart_opts));

    global = authority->priv->js_global->get ();
    if (!global)
      goto fail;

    authority->priv->ac = new JSAutoRealm(authority->priv->cx, global);

    if (!authority->priv->ac)
      goto fail;

    if (!JS::InitRealmStandardClasses (authority->priv->cx))
      goto fail;

    JS::RootedObject polkit(authority->priv->cx);

    authority->priv->js_polkit = new JS::Heap<JSObject *> (JS_NewObject (authority->priv->cx, &js_polkit_class));

    polkit = authority->priv->js_polkit->get ();

    if (!polkit)
      goto fail;

    if (!JS_DefineProperty(authority->priv->cx, global, "polkit", polkit, JSPROP_ENUMERATE))
      goto fail;

    if (!JS_DefineFunctions (authority->priv->cx,
                             polkit,
                             js_polkit_functions))
      goto fail;

    JS::CompileOptions options(authority->priv->cx);
    JS::RootedValue rval(authority->priv->cx);
    JS::SourceText<mozilla::Utf8Unit> source;
    if (!source.init (authority->priv->cx, init_js, strlen (init_js),
                      JS::SourceOwnership::Borrowed))
      goto fail;

    if (!JS::Evaluate (authority->priv->cx, options, source, &rval))
      goto fail;

    if (authority->priv->rules_dirs == NULL)
      {
        authority->priv->rules_dirs = g_new0 (gchar *, 3);
        authority->priv->rules_dirs[0] = g_strdup (PACKAGE_SYSCONF_DIR "/polkit-1/rules.d");
        authority->priv->rules_dirs[1] = g_strdup (PACKAGE_DATA_DIR "/polkit-1/rules.d");
      }

    authority->priv->rkt_context = g_main_context_new ();
    authority->priv->rkt_loop = g_main_loop_new (authority->priv->rkt_context, FALSE);
    g_mutex_init (&authority->priv->rkt_timeout_pending_mutex);

    authority->priv->runaway_killer_thread = g_thread_new ("runaway-killer-thread",
                                                           runaway_killer_thread_func,
                                                           authority);

    setup_file_monitors (authority);
    load_scripts (authority);
  }

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

  runaway_killer_terminate (authority);

  g_mutex_clear (&authority->priv->rkt_timeout_pending_mutex);
  g_main_loop_unref (authority->priv->rkt_loop);
  g_main_context_unref (authority->priv->rkt_context);

  for (n = 0; authority->priv->dir_monitors != NULL && authority->priv->dir_monitors[n] != NULL; n++)
    {
      GFileMonitor *monitor = authority->priv->dir_monitors[n];
      g_signal_handlers_disconnect_by_func (monitor,
                                            (gpointer*)G_CALLBACK (polkit_backend_common_on_dir_monitor_changed),
                                            authority);
      g_object_unref (monitor);
    }
  g_free (authority->priv->dir_monitors);
  g_strfreev (authority->priv->rules_dirs);

  delete authority->priv->ac;
  delete authority->priv->js_global;
  delete authority->priv->js_polkit;

  JS_DestroyContext (authority->priv->cx);

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

  g_type_class_add_private (klass, sizeof (PolkitBackendJsAuthorityPrivate));
}

/* ---------------------------------------------------------------------------------------------------- */

/* authority->priv->cx must be within a request */
static void
set_property_str (PolkitBackendJsAuthority  *authority,
                  JS::HandleObject           obj,
                  const gchar               *name,
                  const gchar               *value)
{
  JS::RootedValue value_jsval(authority->priv->cx);
  if (value)
    {
      JS::ConstUTF8CharsZ chars(value, strlen(value));
      JS::RootedString str(authority->priv->cx, JS_NewStringCopyUTF8Z(authority->priv->cx, chars));
      value_jsval = JS::StringValue (str);
    }
  else
    value_jsval = JS::NullValue ();
  JS_SetProperty (authority->priv->cx, obj, name, value_jsval);
}

/* authority->priv->cx must be within a request */
static void
set_property_strv (PolkitBackendJsAuthority  *authority,
                   JS::HandleObject           obj,
                   const gchar               *name,
                   GPtrArray                 *value)
{
  JS::RootedValue value_jsval(authority->priv->cx);
  JS::RootedValueVector elems(authority->priv->cx);
  guint n;

  if (!elems.resize(value->len))
    g_error ("Unable to resize vector");

  for (n = 0; n < value->len; n++)
    {
      const char *c_string = (const char *) g_ptr_array_index(value, n);
      if (c_string)
        {
          JS::ConstUTF8CharsZ chars(c_string, strlen(c_string));
          JS::RootedString str(authority->priv->cx, JS_NewStringCopyUTF8Z(authority->priv->cx, chars));
          elems[n].setString(str);
        }
      else
        elems[n].setNull ();
    }

  JS::RootedObject array_object(authority->priv->cx, JS::NewArrayObject (authority->priv->cx, elems));

  value_jsval = JS::ObjectValue (*array_object);
  JS_SetProperty (authority->priv->cx, obj, name, value_jsval);
}

/* authority->priv->cx must be within a request */
static void
set_property_int32 (PolkitBackendJsAuthority  *authority,
                    JS::HandleObject           obj,
                    const gchar               *name,
                    gint32                     value)
{
  JS::RootedValue value_jsval(authority->priv->cx);
  value_jsval = JS::Int32Value ((gint32) value);
  JS_SetProperty (authority->priv->cx, obj, name, value_jsval);
}

/* authority->priv->cx must be within a request */
static void
set_property_bool (PolkitBackendJsAuthority  *authority,
                   JS::HandleObject           obj,
                   const gchar               *name,
                   gboolean                   value)
{
  JS::RootedValue value_jsval(authority->priv->cx);
  value_jsval = JS::BooleanValue ((bool) value);
  JS_SetProperty (authority->priv->cx, obj, name, value_jsval);
}

/* ---------------------------------------------------------------------------------------------------- */

/* authority->priv->cx must be within a request */
static gboolean
subject_to_jsval (PolkitBackendJsAuthority  *authority,
                  PolkitSubject             *subject,
                  PolkitIdentity            *user_for_subject,
                  gboolean                   subject_is_local,
                  gboolean                   subject_is_active,
                  JS::MutableHandleValue     out_jsval,
                  GError                   **error)
{
  gboolean ret = FALSE;
  JS::CompileOptions options(authority->priv->cx);
  const char *src;
  JS::RootedObject obj(authority->priv->cx);
  pid_t pid;
  uid_t uid;
  gchar *user_name = NULL;
  GPtrArray *groups = NULL;
  struct passwd *passwd;
  char *seat_str = NULL;
  char *session_str = NULL;
  JS::RootedObject global(authority->priv->cx, authority->priv->js_global->get ());

  src = "new Subject();";
  JS::SourceText<mozilla::Utf8Unit> source;
  if (!source.init (authority->priv->cx, src, strlen (src),
                    JS::SourceOwnership::Borrowed))
  {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Evaluating '%s' failed", src);
      goto out;
  }

  if (!JS::Evaluate (authority->priv->cx, options, source, out_jsval))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Evaluating '%s' failed", src);
      goto out;
    }

  obj = out_jsval.toObjectOrNull();

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject));
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      PolkitSubject *process;
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, error);
      if (process == NULL)
        goto out;
      pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));
      g_object_unref (process);
    }
  else
    {
      g_assert_not_reached ();
    }

#ifdef HAVE_LIBSYSTEMD
  if (sd_pid_get_session (pid, &session_str) == 0)
    {
      if (sd_session_get_seat (session_str, &seat_str) == 0)
        {
          /* do nothing */
        }
    }
#endif /* HAVE_LIBSYSTEMD */

  g_assert (POLKIT_IS_UNIX_USER (user_for_subject));
  uid = polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_for_subject));

  groups = g_ptr_array_new_with_free_func (g_free);

  passwd = getpwuid (uid);
  if (passwd == NULL)
    {
      user_name = g_strdup_printf ("%d", (gint) uid);
      g_warning ("Error looking up info for uid %d: %m", (gint) uid);
    }
  else
    {
      gid_t gids[512];
      int num_gids = 512;

      user_name = g_strdup (passwd->pw_name);

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

  set_property_int32 (authority, obj, "pid", pid);
  set_property_str (authority, obj, "user", user_name);
  set_property_strv (authority, obj, "groups", groups);
  set_property_str (authority, obj, "seat", seat_str);
  set_property_str (authority, obj, "session", session_str);
  set_property_bool (authority, obj, "local", subject_is_local);
  set_property_bool (authority, obj, "active", subject_is_active);

  ret = TRUE;

 out:
  free (session_str);
  free (seat_str);
  g_free (user_name);
  if (groups != NULL)
    g_ptr_array_unref (groups);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/* authority->priv->cx must be within a request */
static gboolean
action_and_details_to_jsval (PolkitBackendJsAuthority  *authority,
                             const gchar               *action_id,
                             PolkitDetails             *details,
                             JS::MutableHandleValue     out_jsval,
                             GError                   **error)
{
  gboolean ret = FALSE;
  JS::CompileOptions options(authority->priv->cx);
  const char *src;
  JS::RootedObject obj(authority->priv->cx);
  gchar **keys;
  guint n;
  JS::RootedObject global(authority->priv->cx, authority->priv->js_global->get ());

  src = "new Action();";
  JS::SourceText<mozilla::Utf8Unit> source;
  if (!source.init (authority->priv->cx, src, strlen (src),
                    JS::SourceOwnership::Borrowed))
  {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Evaluating '%s' failed", src);
      goto out;
  }

  if (!JS::Evaluate (authority->priv->cx, options, source, out_jsval))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "Evaluating '%s' failed", src);
      goto out;
    }

  obj = out_jsval.toObjectOrNull();

  set_property_str (authority, obj, "id", action_id);

  keys = polkit_details_get_keys (details);
  for (n = 0; keys != NULL && keys[n] != NULL; n++)
    {
      gchar *key;
      const gchar *value;
      key = g_strdup_printf ("_detail_%s", keys[n]);
      value = polkit_details_lookup (details, keys[n]);
      set_property_str (authority, obj, key, value);
      g_free (key);
    }
  g_strfreev (keys);

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gpointer
runaway_killer_thread_func (gpointer user_data)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (user_data);

  g_main_context_push_thread_default (authority->priv->rkt_context);
  g_main_loop_run (authority->priv->rkt_loop);
  g_main_context_pop_thread_default (authority->priv->rkt_context);
  return NULL;
}

/* ---------------------------------------------------------------------------------------------------- */

static bool
js_operation_callback (JSContext *cx)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx));
  JSString *val_str;
  JS::RootedValue val(cx);

  /* This callback can be called by the runtime at any time without us causing
   * it by JS_TriggerOperationCallback().
   */
  g_mutex_lock (&authority->priv->rkt_timeout_pending_mutex);
  if (!authority->priv->rkt_timeout_pending)
    {
      g_mutex_unlock (&authority->priv->rkt_timeout_pending_mutex);
      return true;
    }
  authority->priv->rkt_timeout_pending = FALSE;
  g_mutex_unlock (&authority->priv->rkt_timeout_pending_mutex);

  /* Log that we are terminating the script */
  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority), "Terminating runaway script");

  /* Throw an exception - this way the JS code can ignore the runaway script handling */
  JS_ResetInterruptCallback (authority->priv->cx, TRUE);
  val_str = JS_NewStringCopyZ (cx, "Terminating runaway script");
  val = JS::StringValue (val_str);
  JS_SetPendingException (authority->priv->cx, val);
  JS_ResetInterruptCallback (authority->priv->cx, FALSE);
  return false;
}

static gboolean
rkt_on_timeout (gpointer user_data)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (user_data);

  g_mutex_lock (&authority->priv->rkt_timeout_pending_mutex);
  authority->priv->rkt_timeout_pending = TRUE;
  g_mutex_unlock (&authority->priv->rkt_timeout_pending_mutex);

  /* Supposedly this is thread-safe... */
  JS_RequestInterruptCallback (authority->priv->cx);

  /* keep source around so we keep trying to kill even if the JS bit catches the exception
   * thrown in js_operation_callback()
   */
  return TRUE;
}

static void
runaway_killer_setup (PolkitBackendJsAuthority *authority)
{
  g_assert (authority->priv->rkt_source == NULL);

  /* set-up timer for runaway scripts, will be executed in
     runaway_killer_thread, that is one, permanent thread running a glib
     mainloop (rkt_loop) whose context (rkt_context) has a timeout source
     (rkt_source) */
  g_mutex_lock (&authority->priv->rkt_timeout_pending_mutex);
  authority->priv->rkt_timeout_pending = FALSE;
  g_mutex_unlock (&authority->priv->rkt_timeout_pending_mutex);
  authority->priv->rkt_source = g_timeout_source_new_seconds (RUNAWAY_KILLER_TIMEOUT);
  g_source_set_callback (authority->priv->rkt_source, rkt_on_timeout, authority, NULL);
  g_source_attach (authority->priv->rkt_source, authority->priv->rkt_context);

  /* ... rkt_on_timeout() will then poke the JSContext so js_operation_callback() is
   * called... and from there we throw an exception
   */
  JS_AddInterruptCallback (authority->priv->cx, js_operation_callback);
  JS_ResetInterruptCallback (authority->priv->cx, FALSE);
}

static void
runaway_killer_teardown (PolkitBackendJsAuthority *authority)
{
  JS_ResetInterruptCallback (authority->priv->cx, TRUE);

  g_source_destroy (authority->priv->rkt_source);
  g_source_unref (authority->priv->rkt_source);
  authority->priv->rkt_source = NULL;
}

static gboolean
runaway_killer_call_g_main_quit (gpointer user_data)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (user_data);
  g_main_loop_quit (authority->priv->rkt_loop);
  return G_SOURCE_REMOVE;
}

static void
runaway_killer_terminate (PolkitBackendJsAuthority *authority)
{
  GSource *source;

  /* Use a g_idle_source_new () to ensure g_main_loop_quit () is called from
   * inside a running rkt_loop. This prevents a possible race condition, where
   * we could be calling g_main_loop_quit () on the main thread before
   * runaway_killer_thread_func () starts its g_main_loop_run () call;
   * g_main_loop_quit () before g_main_loop_run () does nothing, so in such
   * a case we would not terminate the thread and become blocked in
   * g_thread_join () below.
   */
  g_assert (authority->priv->rkt_loop != NULL);

  source = g_idle_source_new ();
  g_source_set_callback (source, runaway_killer_call_g_main_quit, authority,
			 NULL);
  g_source_attach (source, authority->priv->rkt_context);
  g_source_unref (source);

  g_thread_join (authority->priv->runaway_killer_thread);
}

static bool
execute_script_with_runaway_killer (PolkitBackendJsAuthority *authority,
                                    JS::HandleScript                 script,
                                    JS::MutableHandleValue           rval)
{
  bool ret;

  // tries to JS_ExecuteScript(), may hang for > RUNAWAY_KILLER_TIMEOUT,
  // runaway_killer_thread makes sure the call returns, due to exception
  // injection
  runaway_killer_setup (authority);
  ret = JS_ExecuteScript (authority->priv->cx,
                          script,
                          rval);
  runaway_killer_teardown (authority);

  return ret;
}

static bool
call_js_function_with_runaway_killer (PolkitBackendJsAuthority *authority,
                                      const char               *function_name,
                                      const JS::HandleValueArray     &args,
                                      JS::RootedValue          *rval)
{
  bool ret;
  JS::RootedObject js_polkit(authority->priv->cx, authority->priv->js_polkit->get ());

  runaway_killer_setup (authority);
  ret = JS_CallFunctionName(authority->priv->cx,
                            js_polkit,
                            function_name,
                            args,
                            rval);
  runaway_killer_teardown (authority);
  return ret;
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
  JS::RootedValueArray<2> args(authority->priv->cx);
  JS::RootedValue rval(authority->priv->cx);
  guint n;
  GError *error = NULL;
  JS::RootedString ret_jsstr (authority->priv->cx);
  JS::UniqueChars ret_str;
  gchar **ret_strs = NULL;

  if (!action_and_details_to_jsval (authority, action_id, details, args[0], &error))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error converting action and details to JS object: %s",
                                    error->message);
      g_clear_error (&error);
      goto out;
    }

  if (!subject_to_jsval (authority,
                         subject,
                         user_for_subject,
                         subject_is_local,
                         subject_is_active,
                         args[1],
                         &error))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error converting subject to JS object: %s",
                                    error->message);
      g_clear_error (&error);
      goto out;
    }

  if (!call_js_function_with_runaway_killer (authority,
                                             "_runAdminRules",
                                             args,
                                             &rval))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error evaluating admin rules");
      goto out;
    }

  if (!rval.isString())
    {
      g_warning ("Expected a string");
      goto out;
    }

  ret_jsstr = rval.toString();
  ret_str = JS_EncodeStringToUTF8 (authority->priv->cx, ret_jsstr);
  if (ret_str == NULL)
    {
      g_warning ("Error converting resulting string to UTF-8");
      goto out;
    }

  ret_strs = g_strsplit (ret_str.get(), ",", -1);
  for (n = 0; ret_strs != NULL && ret_strs[n] != NULL; n++)
    {
      const gchar *identity_str = ret_strs[n];
      PolkitIdentity *identity;

      error = NULL;
      identity = polkit_identity_from_string (identity_str, &error);
      if (identity == NULL)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Identity `%s' is not valid, ignoring (%s)",
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

  JS_MaybeGC (authority->priv->cx);

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
  JS::RootedValueArray<2> args(authority->priv->cx);
  JS::RootedValue rval(authority->priv->cx);
  GError *error = NULL;
  JS::RootedString ret_jsstr (authority->priv->cx);
  JS::UniqueChars ret_str;
  gboolean good = FALSE;

  if (!action_and_details_to_jsval (authority, action_id, details, args[0], &error))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error converting action and details to JS object: %s",
                                    error->message);
      g_clear_error (&error);
      goto out;
    }

  if (!subject_to_jsval (authority,
                         subject,
                         user_for_subject,
                         subject_is_local,
                         subject_is_active,
                         args[1],
                         &error))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error converting subject to JS object: %s",
                                    error->message);
      g_clear_error (&error);
      goto out;
    }

  if (!call_js_function_with_runaway_killer (authority,
                                             "_runRules",
                                             args,
                                             &rval))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error evaluating authorization rules");
      goto out;
    }

  if (rval.isNull())
    {
      /* this fine, means there was no match, use implicit authorizations */
      good = TRUE;
      goto out;
    }

  if (!rval.isString())
    {
      g_warning ("Expected a string");
      goto out;
    }

  ret_jsstr = rval.toString();
  ret_str = JS_EncodeStringToUTF8 (authority->priv->cx, ret_jsstr);
  if (ret_str == NULL)
    {
      g_warning ("Error converting resulting string to UTF-8");
      goto out;
    }

  g_strstrip (ret_str.get());
  if (!polkit_implicit_authorization_from_string (ret_str.get(), &ret))
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Returned result `%s' is not valid",
                                    ret_str.get());
      goto out;
    }

  good = TRUE;

 out:
  if (!good)
    ret = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;

  JS_MaybeGC (authority->priv->cx);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static bool
js_polkit_log (JSContext  *cx,
               unsigned    argc,
               JS::Value      *vp)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx));
  bool ret = false;
  JS::UniqueChars s;

  JS::CallArgs args = JS::CallArgsFromVp (argc, vp);

  JS::RootedString jsstr (authority->priv->cx);
  jsstr = args[0].toString ();
  s = JS_EncodeStringToUTF8 (cx, jsstr);
  JS::WarnUTF8 (cx, "%s", s.get());

  ret = true;

  args.rval ().setUndefined (); /* return undefined */

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static bool
js_polkit_spawn (JSContext  *cx,
                 unsigned    js_argc,
                 JS::Value      *vp)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx));
  bool ret = false;
  JS::RootedObject array_object(cx);
  gchar *standard_output = NULL;
  gchar *standard_error = NULL;
  gint exit_status;
  GError *error = NULL;
  JSString *ret_jsstr;
  guint32 array_len;
  gchar **argv = NULL;
  GMainContext *context = NULL;
  GMainLoop *loop = NULL;
  SpawnData data = {0};
  guint n;

  JS::CallArgs args = JS::CallArgsFromVp (js_argc, vp);
  array_object = &args[0].toObject();

  if (!JS::GetArrayLength (cx, array_object, &array_len))
    {
      JS_ReportErrorUTF8 (cx, "Failed to get array length");
      goto out;
    }

  argv = g_new0 (gchar*, array_len + 1);
  for (n = 0; n < array_len; n++)
    {
      JS::RootedValue elem_val(cx);
      JS::UniqueChars s;

      if (!JS_GetElement (cx, array_object, n, &elem_val))
        {
          JS_ReportErrorUTF8 (cx, "Failed to get element %d", n);
          goto out;
        }
      if (!elem_val.isString())
	{
          JS_ReportErrorUTF8 (cx, "Element %d is not a string", n);
          goto out;
	}
      JS::RootedString jsstr (authority->priv->cx);
      jsstr = elem_val.toString();
      s = JS_EncodeStringToUTF8 (cx, jsstr);
      argv[n] = g_strdup (s.get());
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
      JS_ReportErrorUTF8 (cx,
                      "Error spawning helper: %s (%s, %d)",
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
      JS_ReportErrorUTF8 (cx, "%s", gstr->str);
      g_string_free (gstr, TRUE);
      goto out;
    }

  ret = true;

  ret_jsstr = JS_NewStringCopyZ (cx, standard_output);
  args.rval ().setString (ret_jsstr);

 out:
  g_strfreev (argv);
  g_free (standard_output);
  g_free (standard_error);
  g_clear_object (&data.res);
  if (loop != NULL)
    g_main_loop_unref (loop);
  if (context != NULL)
    g_main_context_unref (context);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */


static bool
js_polkit_user_is_in_netgroup (JSContext  *cx,
                               unsigned    argc,
                               JS::Value      *vp)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx));
  bool ret = false;
  JS::UniqueChars user;
  JS::UniqueChars netgroup;
  bool is_in_netgroup = false;

  JS::CallArgs args = JS::CallArgsFromVp (argc, vp);

#ifdef HAVE_SETNETGRENT
  JS::RootedString usrstr (authority->priv->cx);
  usrstr = args[0].toString();
  user = JS_EncodeStringToUTF8 (cx, usrstr);
  JS::RootedString netgstr (authority->priv->cx);
  netgstr = args[1].toString();
  netgroup = JS_EncodeStringToUTF8 (cx, netgstr);

  if (innetgr (netgroup.get(),
               NULL,  /* host */
               user.get(),
               NULL)) /* domain */
    {
      is_in_netgroup =  true;
    }
#endif

  ret = true;

  args.rval ().setBoolean (is_in_netgroup);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */


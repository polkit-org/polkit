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

#include "config.h"
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <glib/gi18n-lib.h>

#include <polkit/polkit.h>
#include "polkitbackendjsauthority.h"

#include <polkit/polkitprivate.h>

#include <systemd/sd-login.h>

#include <jsapi.h>

/**
 * SECTION:polkitbackendjsauthority
 * @title: PolkitBackendJsAuthority
 * @short_description: JS Authority
 * @stability: Unstable
 *
 * An implementation of #PolkitBackendAuthority that reads and
 * evalates Javascript files and supports interaction with
 * authentication agents (virtue of being based on
 * #PolkitBackendInteractiveAuthority).
 */

/* ---------------------------------------------------------------------------------------------------- */

struct _PolkitBackendJsAuthorityPrivate
{
  gchar *rules_dir;
  GFileMonitor *dir_monitor;

  JSRuntime *rt;
  JSContext *cx;
  JSObject *js_global;
  JSObject *js_polkit;

  /* A list of JSObject instances */
  GList *scripts;
};

static void on_dir_monitor_changed (GFileMonitor     *monitor,
                                    GFile            *file,
                                    GFile            *other_file,
                                    GFileMonitorEvent event_type,
                                    gpointer          user_data);

/* ---------------------------------------------------------------------------------------------------- */

enum
{
  PROP_0,
  PROP_RULES_DIR,
};

/* ---------------------------------------------------------------------------------------------------- */

static GList *polkit_backend_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *authority,
                                                                     PolkitSubject                     *caller,
                                                                     PolkitSubject                     *subject,
                                                                     PolkitIdentity                    *user_for_subject,
                                                                     const gchar                       *action_id,
                                                                     PolkitDetails                     *details);

static PolkitImplicitAuthorization polkit_backend_js_authority_check_authorization_sync (
                                                          PolkitBackendInteractiveAuthority *authority,
                                                          PolkitSubject                     *caller,
                                                          PolkitSubject                     *subject,
                                                          PolkitIdentity                    *user_for_subject,
                                                          gboolean                           subject_is_local,
                                                          gboolean                           subject_is_active,
                                                          const gchar                       *action_id,
                                                          PolkitDetails                     *details,
                                                          PolkitImplicitAuthorization        implicit,
                                                          PolkitDetails                     *out_details);

G_DEFINE_TYPE_WITH_CODE (PolkitBackendJsAuthority,
                         polkit_backend_js_authority,
                         POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY,
                         g_io_extension_point_implement (POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME,
                                                         g_define_type_id,
                                                         "js-authority" PACKAGE_VERSION,
                                                         10));

/* ---------------------------------------------------------------------------------------------------- */

static JSClass js_global_class = {
  "global",
  JSCLASS_GLOBAL_FLAGS,
  JS_PropertyStub,
  JS_PropertyStub,
  JS_PropertyStub,
  JS_StrictPropertyStub,
  JS_EnumerateStub,
  JS_ResolveStub,
  JS_ConvertStub,
  JS_FinalizeStub,
  JSCLASS_NO_OPTIONAL_MEMBERS
};

/* ---------------------------------------------------------------------------------------------------- */

static JSClass js_polkit_class = {
  "Polkit",
  0,
  JS_PropertyStub,
  JS_PropertyStub,
  JS_PropertyStub,
  JS_StrictPropertyStub,
  JS_EnumerateStub,
  JS_ResolveStub,
  JS_ConvertStub,
  JS_FinalizeStub,
  JSCLASS_NO_OPTIONAL_MEMBERS
};

static JSBool js_polkit_log (JSContext *cx, uintN argc, jsval *vp);

static JSFunctionSpec js_polkit_functions[] =
{
  JS_FS("log",            js_polkit_log,            0, 0),
  JS_FS_END
};

/* ---------------------------------------------------------------------------------------------------- */

static void report_error (JSContext     *cx,
                          const char    *message,
                          JSErrorReport *report)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx));
  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "%s:%u: %s",
                                report->filename ? report->filename : "<no filename>",
                                (unsigned int) report->lineno,
                                message);
}

static void
polkit_backend_js_authority_init (PolkitBackendJsAuthority *authority)
{
  authority->priv = G_TYPE_INSTANCE_GET_PRIVATE (authority,
                                                 POLKIT_BACKEND_TYPE_JS_AUTHORITY,
                                                 PolkitBackendJsAuthorityPrivate);
}

static void
load_scripts (PolkitBackendJsAuthority  *authority)
{
  GDir *dir = NULL;
  GList *files = NULL;
  GList *l;
  const gchar *name;
  guint num_scripts = 0;
  GError *error = NULL;

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Loading scripts from directory %s",
                                authority->priv->rules_dir);

  dir = g_dir_open (authority->priv->rules_dir,
                    0,
                    &error);
  if (dir == NULL)
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error opening rules directory: %s (%s, %d)\n",
                                    error->message, g_quark_to_string (error->domain), error->code);
      g_clear_error (&error);
      goto out;
    }

  files = NULL;
  while ((name = g_dir_read_name (dir)) != NULL)
    {
      if (g_str_has_suffix (name, ".rules"))
        files = g_list_prepend (files, g_strdup_printf ("%s/%s", authority->priv->rules_dir, name));
    }

  files = g_list_sort (files, (GCompareFunc) g_strcmp0);

  for (l = files; l != NULL; l = l->next)
    {
      const gchar *filename = l->data;
      JSObject *script;

      script = JS_CompileFile (authority->priv->cx,
                               authority->priv->js_global,
                               filename);
      if (script == NULL)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error compiling script %s",
                                        filename);
          continue;
        }

      /* evaluate the script */
      jsval rval;
      if (!JS_ExecuteScript (authority->priv->cx,
                             authority->priv->js_global,
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
                                "Finished loading, compiling and executing %d scripts",
                                num_scripts);

 out:
  g_list_free_full (files, g_free);
  if (dir != NULL)
    g_dir_close (dir);
}

static void
reload_scripts (PolkitBackendJsAuthority *authority)
{
  jsval argv[1] = {0};
  jsval rval = {0};

  if (!JS_CallFunctionName(authority->priv->cx,
                           authority->priv->js_polkit,
                           "_deleteRules",
                           0,
                           argv,
                           &rval))
    {
      /* TODO: syslog? */
      g_printerr ("boo, faileded clearing rules\n");
      goto out;
    }

  load_scripts (authority);
 out:
  ;
}

static void
on_dir_monitor_changed (GFileMonitor     *monitor,
                        GFile            *file,
                        GFile            *other_file,
                        GFileMonitorEvent event_type,
                        gpointer          user_data)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (user_data);

  /* TODO: maybe rate-limit so storms of events are collapsed into one with a 500ms resolution?
   *       Because when editing a file with emacs we get 4-8 events..
   */

  if (file != NULL)
    {
      gchar *name;

      name = g_file_get_basename (file);

      /* g_print ("event_type=%d file=%p name=%s\n", event_type, file, name); */
      if (!g_str_has_prefix (name, ".") &&
          !g_str_has_prefix (name, "#") &&
          g_str_has_suffix (name, ".rules") &&
          (event_type == G_FILE_MONITOR_EVENT_CREATED ||
           event_type == G_FILE_MONITOR_EVENT_DELETED ||
           event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT))
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Reloading scripts");
          reload_scripts (authority);
        }
      g_free (name);
    }
}

static const gchar js_polkit_init[] =
  "function Subject(pid, user, groups, seat, session, local, active) {\n"
  "  this.pid = pid;\n"
  "  this.user = user;\n"
  "  this.groups = groups.split(',');\n"
  "  this.seat = seat;\n"
  "  this.session = session;\n"
  "  this.local = local;\n"
  "  this.active = active;\n"
  "  \n"
  "  this.isInGroup = function(group) {\n"
  "    for (var n = 0; n < this.groups.length; n++) {\n"
  "    if (this.groups[n] == group)\n"
  "      return true;\n"
  "    }\n"
  "    return false;\n"
  "  };\n"
  "  \n"
  "  this.toString = function() {\n"
  "    return '[Subject pid=' + this.pid +\n"
  "                ' seat=' + this.seat +\n"
  "                ' session=' + this.session +\n"
  "                ' local=' + this.local +\n"
  "                ' active=' + this.active +\n"
  "                ' user=' + this.user +\n"
  "                ' groups=' + this.groups + ']';\n"
  "  };\n"
  "}\n"
  "\n"
  "polkit._administratorRuleFuncs = [];\n"
  "polkit.addAdministratorRule = function(callback) {this._administratorRuleFuncs.push(callback);};\n"
  "polkit._runAdministratorRules = function(action, pid, user, groups, seat, session, local, active) {\n"
  "  var ret = null;\n"
  "  var subject = new Subject(pid, user, groups, seat, session, local, active);\n"
  "  for (var n = this._administratorRuleFuncs.length - 1; n >= 0; n--) {\n"
  "    var func = this._administratorRuleFuncs[n];\n"
  "    ret = func(action, subject);\n"
  "    if (ret)\n"
  "      break\n"
  "  }\n"
  "  return ret.join(',');\n"
  "};\n"
  "\n"
  "polkit._authorizationRuleFuncs = [];\n"
  "polkit.addAuthorizationRule = function(callback) {this._authorizationRuleFuncs.push(callback);};\n"
  "polkit._runAuthorizationRules = function(action, pid, user, groups, seat, session, local, active) {\n"
  "  var ret = null;\n"
  "  var subject = new Subject(pid, user, groups, seat, session, local, active);\n"
  "  for (var n = this._authorizationRuleFuncs.length - 1; n >= 0; n--) {\n"
  "    var func = this._authorizationRuleFuncs[n];\n"
  "    ret = func(action, subject);\n"
  "    if (ret)\n"
  "      break\n"
  "  }\n"
  "  return ret;\n"
  "};\n"
  "\n"
  "polkit._deleteRules = function() {\n"
  "  this._administratorRuleFuncs = [];\n"
  "  this._authorizationRuleFuncs = [];\n"
  "};\n"
  "\n"
  "";


static void
polkit_backend_js_authority_constructed (GObject *object)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (object);

  /* TODO: error checking */
  authority->priv->rt = JS_NewRuntime (8L * 1024L * 1024L);
  authority->priv->cx = JS_NewContext (authority->priv->rt, 8192);
  JS_SetOptions (authority->priv->cx,
                 JSOPTION_VAROBJFIX |
                 JSOPTION_JIT |
                 JSOPTION_METHODJIT);
  JS_SetVersion(authority->priv->cx, JSVERSION_LATEST);
  JS_SetErrorReporter(authority->priv->cx, report_error);
  JS_SetContextPrivate (authority->priv->cx, authority);

  authority->priv->js_global = JS_NewCompartmentAndGlobalObject (authority->priv->cx,
                                                                 &js_global_class,
                                                                 NULL);
  JS_InitStandardClasses (authority->priv->cx, authority->priv->js_global);

  authority->priv->js_polkit = JS_DefineObject(authority->priv->cx,
                                               authority->priv->js_global,
                                               "polkit",
                                               &js_polkit_class,
                                               NULL,
                                               JSPROP_ENUMERATE);
  JS_DefineFunctions (authority->priv->cx,
                      authority->priv->js_polkit,
                      js_polkit_functions);

  if (!JS_EvaluateScript (authority->priv->cx,
                          authority->priv->js_global,
                          js_polkit_init,
                          strlen (js_polkit_init),
                          NULL,  /* filename */
                          0,     /* lineno */
                          NULL)) /* rval */
    {
      g_printerr ("Error running init code\n");
    }

  load_scripts (authority);

  G_OBJECT_CLASS (polkit_backend_js_authority_parent_class)->constructed (object);
}

static void
polkit_backend_js_authority_finalize (GObject *object)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (object);

  g_free (authority->priv->rules_dir);
  if (authority->priv->dir_monitor != NULL)
    {
      g_signal_handlers_disconnect_by_func (authority->priv->dir_monitor,
                                            G_CALLBACK (on_dir_monitor_changed),
                                            authority);
      g_object_unref (authority->priv->dir_monitor);
    }

  JS_DestroyContext (authority->priv->cx);
  JS_DestroyRuntime (authority->priv->rt);
  /* JS_ShutDown (); */

  G_OBJECT_CLASS (polkit_backend_js_authority_parent_class)->finalize (object);
}

static void
polkit_backend_js_authority_set_property (GObject      *object,
                                          guint         property_id,
                                          const GValue *value,
                                          GParamSpec   *pspec)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (object);
  GFile *file;
  GError *error;

  switch (property_id)
    {
      case PROP_RULES_DIR:
        g_assert (authority->priv->rules_dir == NULL);
        authority->priv->rules_dir = g_value_dup_string (value);

        file = g_file_new_for_path (authority->priv->rules_dir);
        error = NULL;
        authority->priv->dir_monitor = g_file_monitor_directory (file,
                                                                 G_FILE_MONITOR_NONE,
                                                                 NULL,
                                                                 &error);
        if (authority->priv->dir_monitor == NULL)
          {
            g_warning ("Error monitoring directory %s: %s",
                       authority->priv->rules_dir,
                       error->message);
            g_clear_error (&error);
          }
        else
          {
            g_signal_connect (authority->priv->dir_monitor,
                              "changed",
                              G_CALLBACK (on_dir_monitor_changed),
                              authority);
          }
        break;

      default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static const gchar *
polkit_backend_js_authority_get_name (PolkitBackendAuthority *authority)
{
  return "js";
}

static const gchar *
polkit_backend_js_authority_get_version (PolkitBackendAuthority *authority)
{
  return PACKAGE_VERSION;
}

static PolkitAuthorityFeatures
polkit_backend_js_authority_get_features (PolkitBackendAuthority *authority)
{
  return POLKIT_AUTHORITY_FEATURES_TEMPORARY_AUTHORIZATION;
}

static void
polkit_backend_js_authority_class_init (PolkitBackendJsAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;
  PolkitBackendInteractiveAuthorityClass *interactive_authority_class;


  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize                               = polkit_backend_js_authority_finalize;
  gobject_class->set_property                           = polkit_backend_js_authority_set_property;
  gobject_class->constructed                            = polkit_backend_js_authority_constructed;

  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);
  authority_class->get_name                             = polkit_backend_js_authority_get_name;
  authority_class->get_version                          = polkit_backend_js_authority_get_version;
  authority_class->get_features                         = polkit_backend_js_authority_get_features;

  interactive_authority_class = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_CLASS (klass);
  interactive_authority_class->get_admin_identities     = polkit_backend_js_authority_get_admin_auth_identities;
  interactive_authority_class->check_authorization_sync = polkit_backend_js_authority_check_authorization_sync;

  g_object_class_install_property (gobject_class,
                                   PROP_RULES_DIR,
                                   g_param_spec_string ("rules-dir",
                                                        NULL,
                                                        NULL,
                                                        PACKAGE_SYSCONF_DIR "/polkit-1/rules.d",
                                                        G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE));


  g_type_class_add_private (klass, sizeof (PolkitBackendJsAuthorityPrivate));
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
subject_to_js (PolkitBackendJsAuthority *authority,
               PolkitSubject            *subject,
               PolkitIdentity           *user_for_subject,
               jsval                    *jsval_pid,
               jsval                    *jsval_user,
               jsval                    *jsval_groups,
               jsval                    *jsval_seat,
               jsval                    *jsval_session,
               GError                  **error)
{
  gboolean ret = FALSE;
  JSString *user_name_jstr;
  JSString *groups_jstr;
  JSString *seat_jstr;
  JSString *session_jstr;
  pid_t pid;
  uid_t uid;
  gchar *user_name = NULL;
  GString *groups = NULL;
  struct passwd *passwd;
  char *seat_str = NULL;
  char *session_str = NULL;

  g_return_val_if_fail (jsval_pid != NULL, FALSE);
  g_return_val_if_fail (jsval_user != NULL, FALSE);
  g_return_val_if_fail (jsval_groups != NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

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

  if (sd_pid_get_session (pid, &session_str) == 0)
    {
      sd_session_get_seat (session_str, &seat_str);
    }

  g_assert (POLKIT_IS_UNIX_USER (user_for_subject));
  uid = polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_for_subject));

  groups = g_string_new (NULL);

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
              if (n > 0)
                g_string_append_c (groups, ',');

              group = getgrgid (gids[n]);
              if (group == NULL)
                {
                  g_string_append_printf (groups, "%d", (gint) gids[n]);
                }
              else
                {
                  g_string_append_printf (groups, "%s", group->gr_name);
                }
            }
        }
    }

  user_name_jstr = JS_NewStringCopyZ (authority->priv->cx, user_name);
  groups_jstr = JS_NewStringCopyZ (authority->priv->cx, groups->str);
  seat_jstr = JS_NewStringCopyZ (authority->priv->cx, seat_str);
  session_jstr = JS_NewStringCopyZ (authority->priv->cx, session_str);
  *jsval_pid = INT_TO_JSVAL ((int32) pid);
  *jsval_user = STRING_TO_JSVAL (user_name_jstr);
  *jsval_groups = STRING_TO_JSVAL (groups_jstr);
  *jsval_seat = STRING_TO_JSVAL (seat_jstr);
  *jsval_session = STRING_TO_JSVAL (session_jstr);

  ret = TRUE;

 out:
  /* TODO: are we leaking _jstr ? */
  free (session_str);
  free (seat_str);
  g_free (user_name);
  if (groups != NULL)
    g_string_free (groups, TRUE);
  return ret;
}


static GList *
polkit_backend_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *_authority,
                                                       PolkitSubject                     *caller,
                                                       PolkitSubject                     *subject,
                                                       PolkitIdentity                    *user_for_subject,
                                                       const gchar                       *action_id,
                                                       PolkitDetails                     *details)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (_authority);
  GList *ret = NULL;
  jsval argv[8] = {0};
  jsval rval = {0};
  JSString *action_id_jstr;
  guint n;
  GError *error = NULL;
  JSString *ret_jsstr;
  gchar *ret_str = NULL;
  gchar **ret_strs = NULL;

  if (!subject_to_js (authority, subject, user_for_subject, &argv[1], &argv[2], &argv[3], &argv[4], &argv[5], &error))
    {
      /* TODO: syslog? */
      g_printerr ("Error converting subject: %s\n", error->message);
      g_clear_error (&error);
      goto out;
    }

  action_id_jstr = JS_NewStringCopyZ (authority->priv->cx, action_id);
  argv[0] = STRING_TO_JSVAL (action_id_jstr);
  argv[6] = BOOLEAN_TO_JSVAL (FALSE);//TODO:subject_is_local);
  argv[7] = BOOLEAN_TO_JSVAL (FALSE);//TODO:subject_is_active);

  if (!JS_CallFunctionName(authority->priv->cx,
                           authority->priv->js_polkit,
                           "_runAdministratorRules",
                           8,
                           argv,
                           &rval))
    {
      /* TODO: syslog? */
      g_printerr ("boo, failed\n");
      goto out;
    }

  if (!JSVAL_IS_STRING (rval) && !JSVAL_IS_NULL (rval))
    {
      /* TODO: syslog? */
      g_printerr ("boo, not string\n");
      goto out;
    }

  ret_jsstr = JSVAL_TO_STRING (rval);
  ret_str = g_utf16_to_utf8 (JS_GetStringCharsZ (authority->priv->cx, ret_jsstr), -1, NULL, NULL, NULL);
  if (ret_str == NULL)
    {
      /* TODO: syslog? */
      g_printerr ("boo, error converting to UTF-8\n");
      goto out;
    }

  //g_print ("yay, worked `%s'\n", ret_str);

  ret_strs = g_strsplit (ret_str, ",", -1);
  for (n = 0; ret_strs != NULL && ret_strs[n] != NULL; n++)
    {
      const gchar *identity_str = ret_strs[n];
      PolkitIdentity *identity;

      error = NULL;
      identity = polkit_identity_from_string (identity_str, &error);
      if (identity == NULL)
        {
          /* TODO: syslog? */
          g_printerr ("boo, identity `%s' is not valid, ignoring\n", identity_str);
        }
      else
        {
          ret = g_list_prepend (ret, identity);
        }
    }
  ret = g_list_reverse (ret);

 out:
  g_strfreev (ret_strs);
  g_free (ret_str);
  /* fallback to root password auth */
  if (ret == NULL)
    ret = g_list_prepend (ret, polkit_unix_user_new (0));
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitImplicitAuthorization
polkit_backend_js_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *_authority,
                                                      PolkitSubject                     *caller,
                                                      PolkitSubject                     *subject,
                                                      PolkitIdentity                    *user_for_subject,
                                                      gboolean                           subject_is_local,
                                                      gboolean                           subject_is_active,
                                                      const gchar                       *action_id,
                                                      PolkitDetails                     *details,
                                                      PolkitImplicitAuthorization        implicit,
                                                      PolkitDetails                     *out_details)
{
  PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (_authority);
  PolkitImplicitAuthorization ret = implicit;
  jsval argv[8] = {0};
  jsval rval = {0};
  JSString *action_id_jstr;
  GError *error = NULL;
  JSString *ret_jsstr;
  const jschar *ret_utf16;
  gchar *ret_str = NULL;

  if (!subject_to_js (authority, subject, user_for_subject, &argv[1], &argv[2], &argv[3], &argv[4], &argv[5], &error))
    {
      /* TODO: syslog? */
      g_printerr ("Error converting subject: %s\n", error->message);
      g_clear_error (&error);
      goto out;
    }

  action_id_jstr = JS_NewStringCopyZ (authority->priv->cx, action_id);
  argv[0] = STRING_TO_JSVAL (action_id_jstr);
  argv[6] = BOOLEAN_TO_JSVAL (subject_is_local);
  argv[7] = BOOLEAN_TO_JSVAL (subject_is_active);

  if (!JS_CallFunctionName(authority->priv->cx,
                           authority->priv->js_polkit,
                           "_runAuthorizationRules",
                           8,
                           argv,
                           &rval))
    {
      /* TODO: syslog? */
      g_printerr ("boo, failed\n");
      goto out;
    }

  if (!JSVAL_IS_STRING (rval) && !JSVAL_IS_NULL (rval))
    {
      /* TODO: syslog? */
      g_printerr ("boo, not string\n");
      goto out;
    }

  ret_jsstr = JSVAL_TO_STRING (rval);
  if (ret_jsstr == NULL)
    {
      /* TODO: syslog? */
      g_printerr ("boo, string is null\n");
      goto out;
    }

  ret_utf16 = JS_GetStringCharsZ (authority->priv->cx, ret_jsstr);
  ret_str = g_utf16_to_utf8 (ret_utf16, -1, NULL, NULL, NULL);
  if (ret_str == NULL)
    {
      /* TODO: syslog? */
      g_printerr ("boo, error converting to UTF-8\n");
      goto out;
    }

  if (!polkit_implicit_authorization_from_string (ret_str, &ret))
    {
      /* TODO: syslog? */
      g_printerr ("boo, returned result `%s' is not valid\n", ret_str);
      goto out;
    }

  g_print ("yay, worked `%s'\n", ret_str);

 out:
  g_free (ret_str);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static JSBool
js_polkit_log (JSContext  *cx,
               uintN       argc,
               jsval      *vp)
{
  /* PolkitBackendJsAuthority *authority = POLKIT_BACKEND_JS_AUTHORITY (JS_GetContextPrivate (cx)); */
  JSBool ret = JS_FALSE;
  JSString *str;
  char *s;

  if (!JS_ConvertArguments (cx, argc, JS_ARGV (cx, vp), "S", &str))
    goto out;

  s = JS_EncodeString (cx, str);
  JS_ReportWarning (cx, s);
  JS_free (cx, s);

  ret = JS_TRUE;

  JS_SET_RVAL (cx, vp, JSVAL_VOID);  /* return undefined */
 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

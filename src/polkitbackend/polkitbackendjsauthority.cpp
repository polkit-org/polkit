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
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_NETGROUP_H
#include <netgroup.h>
#else
#include <netdb.h>
#endif
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <glib/gi18n-lib.h>

#include <polkit/polkit.h>
#include "polkitbackendjsauthority.h"

#include <polkit/polkitprivate.h>

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-login.h>
#endif /* HAVE_LIBSYSTEMD */

#include <js/CompilationAndEvaluation.h>
#include <js/ContextOptions.h>
#include <js/Initialization.h>
#include <js/Realm.h>
#include <js/SourceText.h>
#include <js/Warnings.h>
#include <js/Array.h>
#include <jsapi.h>

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
 * An implementation of #PolkitBackendAuthority that reads and
 * evalates Javascript files and supports interaction with
 * authentication agents (virtue of being based on
 * #PolkitBackendInteractiveAuthority).
 */

/* ---------------------------------------------------------------------------------------------------- */

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

static void utils_spawn (const gchar *const  *argv,
                         guint                timeout_seconds,
                         GCancellable        *cancellable,
                         GAsyncReadyCallback  callback,
                         gpointer             user_data);

gboolean utils_spawn_finish (GAsyncResult   *res,
                             gint           *out_exit_status,
                             gchar         **out_standard_output,
                             gchar         **out_standard_error,
                             GError        **error);

static void on_dir_monitor_changed (GFileMonitor     *monitor,
                                    GFile            *file,
                                    GFile            *other_file,
                                    GFileMonitorEvent event_type,
                                    gpointer          user_data);

/* ---------------------------------------------------------------------------------------------------- */

enum
{
  PROP_0,
  PROP_RULES_DIRS,
};

/* ---------------------------------------------------------------------------------------------------- */

static gpointer runaway_killer_thread_func (gpointer user_data);
static void runaway_killer_terminate (PolkitBackendJsAuthority *authority);

static GList *polkit_backend_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *authority,
                                                                     PolkitSubject                     *caller,
                                                                     PolkitSubject                     *subject,
                                                                     PolkitIdentity                    *user_for_subject,
                                                                     gboolean                           subject_is_local,
                                                                     gboolean                           subject_is_active,
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
                                                          PolkitImplicitAuthorization        implicit);

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
  nullptr,  // hasInstance
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
  nullptr,  // hasInstance
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

static gint
rules_file_name_cmp (const gchar *a,
                     const gchar *b)
{
  gint ret;
  const gchar *a_base;
  const gchar *b_base;

  a_base = strrchr (a, '/');
  b_base = strrchr (b, '/');

  g_assert (a_base != NULL);
  g_assert (b_base != NULL);
  a_base += 1;
  b_base += 1;

  ret = g_strcmp0 (a_base, b_base);
  if (ret == 0)
    {
      /* /etc wins over /usr */
      ret = g_strcmp0 (a, b);
      g_assert (ret != 0);
    }

  return ret;
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

  files = g_list_sort (files, (GCompareFunc) rules_file_name_cmp);

  for (l = files; l != NULL; l = l->next)
    {
      const gchar *filename = (gchar *)l->data;
      GFile *file = g_file_new_for_path (filename);
      char *contents;
      gsize len;
      if (!g_file_load_contents (file, NULL, &contents, &len, NULL, NULL))
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error compiling script %s",
                                        filename);
          g_object_unref (file);
          continue;
        }

      g_object_unref (file);

      JS::SourceText<mozilla::Utf8Unit> source;
      if (!source.init (authority->priv->cx, contents, len,
                        JS::SourceOwnership::Borrowed))
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error compiling script %s",
                                        filename);
          g_free (contents);
          continue;
        }
      JS::CompileOptions options(authority->priv->cx);
      JS::RootedScript script(authority->priv->cx,
                              JS::Compile (authority->priv->cx, options, source));
      if (!script)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Error compiling script %s",
                                        filename);
          g_free (contents);
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
          g_free (contents);
          continue;
        }

      //g_print ("Successfully loaded and evaluated script `%s'\n", filename);

      g_free (contents);
      num_scripts++;
    }

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Finished loading, compiling and executing %d rules",
                                num_scripts);
  g_list_free_full (files, g_free);
}

static void
reload_scripts (PolkitBackendJsAuthority *authority)
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
                                        "Reloading rules");
          reload_scripts (authority);
        }
      g_free (name);
    }
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
                            G_CALLBACK (on_dir_monitor_changed),
                            authority);
          g_ptr_array_add (p, monitor);
        }
    }
  g_ptr_array_add (p, NULL);
  authority->priv->dir_monitors = (GFileMonitor**) g_ptr_array_free (p, FALSE);
}

static void
polkit_backend_js_authority_constructed (GObject *object)
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

static void
polkit_backend_js_authority_finalize (GObject *object)
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
                                            (gpointer*)G_CALLBACK (on_dir_monitor_changed),
                                            authority);
      g_object_unref (monitor);
    }
  g_free (authority->priv->dir_monitors);
  g_strfreev (authority->priv->rules_dirs);

  delete authority->priv->ac;
  delete authority->priv->js_global;
  delete authority->priv->js_polkit;

  JS_DestroyContext (authority->priv->cx);
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
                                   PROP_RULES_DIRS,
                                   g_param_spec_boxed ("rules-dirs",
                                                       NULL,
                                                       NULL,
                                                       G_TYPE_STRV,
                                                       GParamFlags(G_PARAM_CONSTRUCT_ONLY | G_PARAM_WRITABLE)));


  g_type_class_add_private (klass, sizeof (PolkitBackendJsAuthorityPrivate));

  JS_Init ();
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

  /* set-up timer for runaway scripts, will be executed in runaway_killer_thread */
  g_mutex_lock (&authority->priv->rkt_timeout_pending_mutex);
  authority->priv->rkt_timeout_pending = FALSE;
  g_mutex_unlock (&authority->priv->rkt_timeout_pending_mutex);
  authority->priv->rkt_source = g_timeout_source_new_seconds (15);
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

static GList *
polkit_backend_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *_authority,
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

static PolkitImplicitAuthorization
polkit_backend_js_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *_authority,
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

static const gchar *
get_signal_name (gint signal_number)
{
  switch (signal_number)
    {
#define _HANDLE_SIG(sig) case sig: return #sig;
    _HANDLE_SIG (SIGHUP);
    _HANDLE_SIG (SIGINT);
    _HANDLE_SIG (SIGQUIT);
    _HANDLE_SIG (SIGILL);
    _HANDLE_SIG (SIGABRT);
    _HANDLE_SIG (SIGFPE);
    _HANDLE_SIG (SIGKILL);
    _HANDLE_SIG (SIGSEGV);
    _HANDLE_SIG (SIGPIPE);
    _HANDLE_SIG (SIGALRM);
    _HANDLE_SIG (SIGTERM);
    _HANDLE_SIG (SIGUSR1);
    _HANDLE_SIG (SIGUSR2);
    _HANDLE_SIG (SIGCHLD);
    _HANDLE_SIG (SIGCONT);
    _HANDLE_SIG (SIGSTOP);
    _HANDLE_SIG (SIGTSTP);
    _HANDLE_SIG (SIGTTIN);
    _HANDLE_SIG (SIGTTOU);
    _HANDLE_SIG (SIGBUS);
#ifdef SIGPOLL
    _HANDLE_SIG (SIGPOLL);
#endif
    _HANDLE_SIG (SIGPROF);
    _HANDLE_SIG (SIGSYS);
    _HANDLE_SIG (SIGTRAP);
    _HANDLE_SIG (SIGURG);
    _HANDLE_SIG (SIGVTALRM);
    _HANDLE_SIG (SIGXCPU);
    _HANDLE_SIG (SIGXFSZ);
#undef _HANDLE_SIG
    default:
      break;
    }
  return "UNKNOWN_SIGNAL";
}

typedef struct
{
  GMainLoop *loop;
  GAsyncResult *res;
} SpawnData;

static void
spawn_cb (GObject       *source_object,
          GAsyncResult  *res,
          gpointer       user_data)
{
  SpawnData *data = (SpawnData *)user_data;
  data->res = (GAsyncResult*)g_object_ref (res);
  g_main_loop_quit (data->loop);
}

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
  utils_spawn ((const gchar *const *) argv,
               10, /* timeout_seconds */
               NULL, /* cancellable */
               spawn_cb,
               &data);

  g_main_loop_run (loop);

  g_main_context_pop_thread_default (context);

  if (!utils_spawn_finish (data.res,
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
                                  get_signal_name (WTERMSIG (exit_status)),
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

  ret = true;

  args.rval ().setBoolean (is_in_netgroup);

  return ret;
}



/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  GSimpleAsyncResult *simple; /* borrowed reference */
  GMainContext *main_context; /* may be NULL */

  GCancellable *cancellable;  /* may be NULL */
  gulong cancellable_handler_id;

  GPid child_pid;
  gint child_stdout_fd;
  gint child_stderr_fd;

  GIOChannel *child_stdout_channel;
  GIOChannel *child_stderr_channel;

  GSource *child_watch_source;
  GSource *child_stdout_source;
  GSource *child_stderr_source;

  guint timeout_seconds;
  gboolean timed_out;
  GSource *timeout_source;

  GString *child_stdout;
  GString *child_stderr;

  gint exit_status;
} UtilsSpawnData;

static void
utils_child_watch_from_release_cb (GPid     pid,
                                   gint     status,
                                   gpointer user_data)
{
}

static void
utils_spawn_data_free (UtilsSpawnData *data)
{
  if (data->timeout_source != NULL)
    {
      g_source_destroy (data->timeout_source);
      data->timeout_source = NULL;
    }

  /* Nuke the child, if necessary */
  if (data->child_watch_source != NULL)
    {
      g_source_destroy (data->child_watch_source);
      data->child_watch_source = NULL;
    }

  if (data->child_pid != 0)
    {
      GSource *source;
      kill (data->child_pid, SIGTERM);
      /* OK, we need to reap for the child ourselves - we don't want
       * to use waitpid() because that might block the calling
       * thread (the child might handle SIGTERM and use several
       * seconds for cleanup/rollback).
       *
       * So we use GChildWatch instead.
       *
       * Avoid taking a references to ourselves. but note that we need
       * to pass the GSource so we can nuke it once handled.
       */
      source = g_child_watch_source_new (data->child_pid);
      g_source_set_callback (source,
                             (GSourceFunc) utils_child_watch_from_release_cb,
                             source,
                             (GDestroyNotify) g_source_destroy);
      /* attach source to the global default main context */
      g_source_attach (source, NULL);
      g_source_unref (source);
      data->child_pid = 0;
    }

  if (data->child_stdout != NULL)
    {
      g_string_free (data->child_stdout, TRUE);
      data->child_stdout = NULL;
    }

  if (data->child_stderr != NULL)
    {
      g_string_free (data->child_stderr, TRUE);
      data->child_stderr = NULL;
    }

  if (data->child_stdout_channel != NULL)
    {
      g_io_channel_unref (data->child_stdout_channel);
      data->child_stdout_channel = NULL;
    }
  if (data->child_stderr_channel != NULL)
    {
      g_io_channel_unref (data->child_stderr_channel);
      data->child_stderr_channel = NULL;
    }

  if (data->child_stdout_source != NULL)
    {
      g_source_destroy (data->child_stdout_source);
      data->child_stdout_source = NULL;
    }
  if (data->child_stderr_source != NULL)
    {
      g_source_destroy (data->child_stderr_source);
      data->child_stderr_source = NULL;
    }

  if (data->child_stdout_fd != -1)
    {
      g_warn_if_fail (close (data->child_stdout_fd) == 0);
      data->child_stdout_fd = -1;
    }
  if (data->child_stderr_fd != -1)
    {
      g_warn_if_fail (close (data->child_stderr_fd) == 0);
      data->child_stderr_fd = -1;
    }

  if (data->cancellable_handler_id > 0)
    {
      g_cancellable_disconnect (data->cancellable, data->cancellable_handler_id);
      data->cancellable_handler_id = 0;
    }

  if (data->main_context != NULL)
    g_main_context_unref (data->main_context);

  if (data->cancellable != NULL)
    g_object_unref (data->cancellable);

  g_slice_free (UtilsSpawnData, data);
}

/* called in the thread where @cancellable was cancelled */
static void
utils_on_cancelled (GCancellable *cancellable,
                    gpointer      user_data)
{
  UtilsSpawnData *data = (UtilsSpawnData *)user_data;
  GError *error;

  error = NULL;
  g_warn_if_fail (g_cancellable_set_error_if_cancelled (cancellable, &error));
  g_simple_async_result_take_error (data->simple, error);
  g_simple_async_result_complete_in_idle (data->simple);
  g_object_unref (data->simple);
}

static gboolean
utils_read_child_stderr (GIOChannel *channel,
                         GIOCondition condition,
                         gpointer user_data)
{
  UtilsSpawnData *data = (UtilsSpawnData *)user_data;
  gchar buf[1024];
  gsize bytes_read;

  g_io_channel_read_chars (channel, buf, sizeof buf, &bytes_read, NULL);
  g_string_append_len (data->child_stderr, buf, bytes_read);
  return TRUE;
}

static gboolean
utils_read_child_stdout (GIOChannel *channel,
                         GIOCondition condition,
                         gpointer user_data)
{
  UtilsSpawnData *data = (UtilsSpawnData *)user_data;
  gchar buf[1024];
  gsize bytes_read;

  g_io_channel_read_chars (channel, buf, sizeof buf, &bytes_read, NULL);
  g_string_append_len (data->child_stdout, buf, bytes_read);
  return TRUE;
}

static void
utils_child_watch_cb (GPid     pid,
                      gint     status,
                      gpointer user_data)
{
  UtilsSpawnData *data = (UtilsSpawnData *)user_data;
  gchar *buf;
  gsize buf_size;

  if (g_io_channel_read_to_end (data->child_stdout_channel, &buf, &buf_size, NULL) == G_IO_STATUS_NORMAL)
    {
      g_string_append_len (data->child_stdout, buf, buf_size);
      g_free (buf);
    }
  if (g_io_channel_read_to_end (data->child_stderr_channel, &buf, &buf_size, NULL) == G_IO_STATUS_NORMAL)
    {
      g_string_append_len (data->child_stderr, buf, buf_size);
      g_free (buf);
    }

  data->exit_status = status;

  /* ok, child watch is history, make sure we don't free it in spawn_data_free() */
  data->child_pid = 0;
  data->child_watch_source = NULL;

  /* we're done */
  g_simple_async_result_complete_in_idle (data->simple);
  g_object_unref (data->simple);
}

static gboolean
utils_timeout_cb (gpointer user_data)
{
  UtilsSpawnData *data = (UtilsSpawnData *)user_data;

  data->timed_out = TRUE;

  /* ok, timeout is history, make sure we don't free it in spawn_data_free() */
  data->timeout_source = NULL;

  /* we're done */
  g_simple_async_result_complete_in_idle (data->simple);
  g_object_unref (data->simple);

  return FALSE; /* remove source */
}

static void
utils_spawn (const gchar *const  *argv,
             guint                timeout_seconds,
             GCancellable        *cancellable,
             GAsyncReadyCallback  callback,
             gpointer             user_data)
{
  UtilsSpawnData *data;
  GError *error;

  data = g_slice_new0 (UtilsSpawnData);
  data->timeout_seconds = timeout_seconds;
  data->simple = g_simple_async_result_new (NULL,
                                            callback,
                                            user_data,
                                            (gpointer*)utils_spawn);
  data->main_context = g_main_context_get_thread_default ();
  if (data->main_context != NULL)
    g_main_context_ref (data->main_context);

  data->cancellable = cancellable != NULL ? (GCancellable*)g_object_ref (cancellable) : NULL;

  data->child_stdout = g_string_new (NULL);
  data->child_stderr = g_string_new (NULL);
  data->child_stdout_fd = -1;
  data->child_stderr_fd = -1;

  /* the life-cycle of UtilsSpawnData is tied to its GSimpleAsyncResult */
  g_simple_async_result_set_op_res_gpointer (data->simple, data, (GDestroyNotify) utils_spawn_data_free);

  error = NULL;
  if (data->cancellable != NULL)
    {
      /* could already be cancelled */
      error = NULL;
      if (g_cancellable_set_error_if_cancelled (data->cancellable, &error))
        {
          g_simple_async_result_take_error (data->simple, error);
          g_simple_async_result_complete_in_idle (data->simple);
          g_object_unref (data->simple);
          goto out;
        }

      data->cancellable_handler_id = g_cancellable_connect (data->cancellable,
                                                            G_CALLBACK (utils_on_cancelled),
                                                            data,
                                                            NULL);
    }

  error = NULL;
  if (!g_spawn_async_with_pipes (NULL, /* working directory */
                                 (gchar **) argv,
                                 NULL, /* envp */
                                 GSpawnFlags(G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD),
                                 NULL, /* child_setup */
                                 NULL, /* child_setup's user_data */
                                 &(data->child_pid),
                                 NULL, /* gint *stdin_fd */
                                 &(data->child_stdout_fd),
                                 &(data->child_stderr_fd),
                                 &error))
    {
      g_prefix_error (&error, "Error spawning: ");
      g_simple_async_result_take_error (data->simple, error);
      g_simple_async_result_complete_in_idle (data->simple);
      g_object_unref (data->simple);
      goto out;
    }

  if (timeout_seconds > 0)
    {
      data->timeout_source = g_timeout_source_new_seconds (timeout_seconds);
      g_source_set_priority (data->timeout_source, G_PRIORITY_DEFAULT);
      g_source_set_callback (data->timeout_source, utils_timeout_cb, data, NULL);
      g_source_attach (data->timeout_source, data->main_context);
      g_source_unref (data->timeout_source);
    }

  data->child_watch_source = g_child_watch_source_new (data->child_pid);
  g_source_set_callback (data->child_watch_source, (GSourceFunc) utils_child_watch_cb, data, NULL);
  g_source_attach (data->child_watch_source, data->main_context);
  g_source_unref (data->child_watch_source);

  data->child_stdout_channel = g_io_channel_unix_new (data->child_stdout_fd);
  g_io_channel_set_flags (data->child_stdout_channel, G_IO_FLAG_NONBLOCK, NULL);
  data->child_stdout_source = g_io_create_watch (data->child_stdout_channel, G_IO_IN);
  g_source_set_callback (data->child_stdout_source, (GSourceFunc) utils_read_child_stdout, data, NULL);
  g_source_attach (data->child_stdout_source, data->main_context);
  g_source_unref (data->child_stdout_source);

  data->child_stderr_channel = g_io_channel_unix_new (data->child_stderr_fd);
  g_io_channel_set_flags (data->child_stderr_channel, G_IO_FLAG_NONBLOCK, NULL);
  data->child_stderr_source = g_io_create_watch (data->child_stderr_channel, G_IO_IN);
  g_source_set_callback (data->child_stderr_source, (GSourceFunc) utils_read_child_stderr, data, NULL);
  g_source_attach (data->child_stderr_source, data->main_context);
  g_source_unref (data->child_stderr_source);

 out:
  ;
}

gboolean
utils_spawn_finish (GAsyncResult   *res,
                    gint           *out_exit_status,
                    gchar         **out_standard_output,
                    gchar         **out_standard_error,
                    GError        **error)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);
  UtilsSpawnData *data;
  gboolean ret = FALSE;

  g_return_val_if_fail (G_IS_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == utils_spawn);

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

  data = (UtilsSpawnData*)g_simple_async_result_get_op_res_gpointer (simple);

  if (data->timed_out)
    {
      g_set_error (error,
                   G_IO_ERROR,
                   G_IO_ERROR_TIMED_OUT,
                   "Timed out after %d seconds",
                   data->timeout_seconds);
      goto out;
    }

  if (out_exit_status != NULL)
    *out_exit_status = data->exit_status;

  if (out_standard_output != NULL)
    *out_standard_output = g_strdup (data->child_stdout->str);

  if (out_standard_error != NULL)
    *out_standard_error = g_strdup (data->child_stderr->str);

  ret = TRUE;

 out:
  return ret;
}

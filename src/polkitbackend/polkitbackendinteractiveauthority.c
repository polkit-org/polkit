/*
 * Copyright (C) 2008 Red Hat, Inc.
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
#ifdef HAVE_NETGROUP_H
#include <netgroup.h>
#else
#include <netdb.h>
#endif
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>

#include <polkit/polkit.h>
#include "polkitbackendinteractiveauthority.h"
#include "polkitbackendactionpool.h"
#include "polkitbackendsessionmonitor.h"

#include <polkit/polkitprivate.h>

/**
 * SECTION:polkitbackendinteractiveauthority
 * @title: PolkitBackendInteractiveAuthority
 * @short_description: Interactive Authority
 * @stability: Unstable
 *
 * An subclass of #PolkitBackendAuthority that supports interaction
 * with authentication agents.
 */

/* ---------------------------------------------------------------------------------------------------- */

typedef struct TemporaryAuthorizationStore TemporaryAuthorizationStore;

static TemporaryAuthorizationStore *temporary_authorization_store_new (PolkitBackendInteractiveAuthority *authority);
static void                         temporary_authorization_store_free (TemporaryAuthorizationStore *store);

static gboolean temporary_authorization_store_has_authorization (TemporaryAuthorizationStore *store,
                                                                 PolkitSubject               *subject,
                                                                 const gchar                 *action_id,
                                                                 const gchar                **out_tmp_authz_id);

static const gchar *temporary_authorization_store_add_authorization (TemporaryAuthorizationStore *store,
                                                                     PolkitSubject               *subject,
                                                                     PolkitSubject               *session,
                                                                     const gchar                 *action_id);

static void temporary_authorization_store_remove_authorizations_for_system_bus_name (TemporaryAuthorizationStore *store,
                                                                                     const gchar *name);

/* ---------------------------------------------------------------------------------------------------- */

struct AuthenticationAgent;
typedef struct AuthenticationAgent AuthenticationAgent;

struct AuthenticationSession;
typedef struct AuthenticationSession AuthenticationSession;

typedef void (*AuthenticationAgentCallback) (AuthenticationAgent         *agent,
                                             PolkitSubject               *subject,
                                             PolkitIdentity              *user_of_subject,
                                             PolkitSubject               *caller,
                                             PolkitBackendInteractiveAuthority *authority,
                                             const gchar                 *action_id,
                                             PolkitDetails               *details,
                                             PolkitImplicitAuthorization  implicit_authorization,
                                             gboolean                     authentication_success,
                                             gboolean                     was_dismissed,
                                             PolkitIdentity              *authenticated_identity,
                                             gpointer                     user_data);

static AuthenticationAgent *authentication_agent_ref   (AuthenticationAgent *agent);
static void                 authentication_agent_unref (AuthenticationAgent *agent);

static void                authentication_agent_initiate_challenge (AuthenticationAgent         *agent,
                                                                    PolkitSubject               *subject,
                                                                    PolkitIdentity              *user_of_subject,
                                                                    PolkitBackendInteractiveAuthority *authority,
                                                                    const gchar                 *action_id,
                                                                    PolkitDetails               *details,
                                                                    PolkitSubject               *caller,
                                                                    PolkitImplicitAuthorization  implicit_authorization,
                                                                    GCancellable                *cancellable,
                                                                    AuthenticationAgentCallback  callback,
                                                                    gpointer                     user_data);

static PolkitSubject *authentication_agent_get_scope (AuthenticationAgent *agent);

static AuthenticationAgent *get_authentication_agent_for_subject (PolkitBackendInteractiveAuthority *authority,
                                                                  PolkitSubject *subject);


static AuthenticationSession *get_authentication_session_for_uid_and_cookie (PolkitBackendInteractiveAuthority *authority,
                                                                             uid_t                              uid,
                                                                             const gchar                       *cookie);

static GList *get_authentication_sessions_initiated_by_system_bus_unique_name (PolkitBackendInteractiveAuthority *authority,
                                                                               const gchar *system_bus_unique_name);

static void authentication_session_cancel (AuthenticationSession *session);

/* ---------------------------------------------------------------------------------------------------- */

static void polkit_backend_interactive_authority_system_bus_name_owner_changed (PolkitBackendInteractiveAuthority   *authority,
                                                                                const gchar              *name,
                                                                                const gchar              *old_owner,
                                                                                const gchar              *new_owner);

static GList *polkit_backend_interactive_authority_enumerate_actions  (PolkitBackendAuthority   *authority,
                                                                 PolkitSubject            *caller,
                                                                 const gchar              *locale,
                                                                 GError                  **error);

static void polkit_backend_interactive_authority_check_authorization (PolkitBackendAuthority        *authority,
                                                                PolkitSubject                 *caller,
                                                                PolkitSubject                 *subject,
                                                                const gchar                   *action_id,
                                                                PolkitDetails                 *details,
                                                                PolkitCheckAuthorizationFlags  flags,
                                                                GCancellable                  *cancellable,
                                                                GAsyncReadyCallback            callback,
                                                                gpointer                       user_data);

static PolkitAuthorizationResult *polkit_backend_interactive_authority_check_authorization_finish (
                                                                 PolkitBackendAuthority  *authority,
                                                                 GAsyncResult            *res,
                                                                 GError                 **error);

static PolkitAuthorizationResult *check_authorization_sync (PolkitBackendAuthority         *authority,
                                                            PolkitSubject                  *caller,
                                                            PolkitSubject                  *subject,
                                                            const gchar                    *action_id,
                                                            PolkitDetails                  *details,
                                                            PolkitCheckAuthorizationFlags   flags,
                                                            PolkitImplicitAuthorization    *out_implicit_authorization,
                                                            gboolean                        checking_imply,
                                                            GError                        **error);

static gboolean polkit_backend_interactive_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                                                    PolkitSubject            *caller,
                                                                                    PolkitSubject            *subject,
                                                                                    const gchar              *locale,
                                                                                    const gchar              *object_path,
                                                                                    GVariant                 *options,
                                                                                    GError                  **error);

static gboolean polkit_backend_interactive_authority_unregister_authentication_agent (PolkitBackendAuthority   *authority,
                                                                                      PolkitSubject            *caller,
                                                                                      PolkitSubject            *subject,
                                                                                      const gchar              *object_path,
                                                                                      GError                  **error);

static gboolean polkit_backend_interactive_authority_authentication_agent_response (PolkitBackendAuthority   *authority,
                                                                              PolkitSubject            *caller,
                                                                              uid_t                     uid,
                                                                              const gchar              *cookie,
                                                                              PolkitIdentity           *identity,
                                                                              GError                  **error);

static GList *polkit_backend_interactive_authority_enumerate_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                                                       PolkitSubject            *caller,
                                                                                       PolkitSubject            *subject,
                                                                                       GError                  **error);


static gboolean polkit_backend_interactive_authority_revoke_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                                                      PolkitSubject            *caller,
                                                                                      PolkitSubject            *subject,
                                                                                      GError                  **error);

static gboolean polkit_backend_interactive_authority_revoke_temporary_authorization_by_id (PolkitBackendAuthority   *authority,
                                                                                           PolkitSubject            *caller,
                                                                                           const gchar              *id,
                                                                                           GError                  **error);


/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  PolkitBackendActionPool *action_pool;

  PolkitBackendSessionMonitor *session_monitor;

  TemporaryAuthorizationStore *temporary_authorization_store;

  /* Maps from PolkitSubject* to AuthenticationAgent* - currently the
   * following PolkitSubject-derived types are used
   *
   *  - PolkitSystemBusName - for authentication agents handling interaction for a single well-known name
   *    - typically pkexec(1) launched via e.g. ssh(1) or login(1)
   *
   *  - PolkitUnixSession - for authentication agents handling interaction for a whole login session
   *    - typically a desktop environment session
   *
   */
  GHashTable *hash_scope_to_authentication_agent;

  GDBusConnection *system_bus_connection;
  guint name_owner_changed_signal_id;

  guint64 agent_serial;
} PolkitBackendInteractiveAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

G_DEFINE_TYPE (PolkitBackendInteractiveAuthority,
               polkit_backend_interactive_authority,
               POLKIT_BACKEND_TYPE_AUTHORITY);

#define POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY, PolkitBackendInteractiveAuthorityPrivate))

static gboolean
identity_is_root_user (PolkitIdentity *user)
{
  if (!POLKIT_IS_UNIX_USER (user))
    return FALSE;
  return polkit_unix_user_get_uid (POLKIT_UNIX_USER (user)) == 0;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
action_pool_changed (PolkitBackendActionPool *action_pool,
                     PolkitBackendInteractiveAuthority *authority)
{
  g_signal_emit_by_name (authority, "changed");
}


/* ---------------------------------------------------------------------------------------------------- */

static void
on_name_owner_changed_signal (GDBusConnection *connection,
                              const gchar     *sender_name,
                              const gchar     *object_path,
                              const gchar     *interface_name,
                              const gchar     *signal_name,
                              GVariant        *parameters,
                              gpointer         user_data)
{
  PolkitBackendInteractiveAuthority *authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (user_data);
  const gchar *name;
  const gchar *old_owner;
  const gchar *new_owner;

  g_variant_get (parameters,
                 "(&s&s&s)",
                 &name,
                 &old_owner,
                 &new_owner);

  polkit_backend_interactive_authority_system_bus_name_owner_changed (authority,
                                                                      name,
                                                                      old_owner,
                                                                      new_owner);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
on_session_monitor_changed (PolkitBackendSessionMonitor *monitor,
                            gpointer                     user_data)
{
  PolkitBackendInteractiveAuthority *authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (user_data);
  g_signal_emit_by_name (authority, "changed");
}

static void
polkit_backend_interactive_authority_init (PolkitBackendInteractiveAuthority *authority)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GFile *directory;
  GError *error;

  /* Force registering error domain */
  (void)POLKIT_ERROR;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  directory = g_file_new_for_path (PACKAGE_DATA_DIR "/polkit-1/actions");
  priv->action_pool = polkit_backend_action_pool_new (directory);
  g_object_unref (directory);
  g_signal_connect (priv->action_pool,
                    "changed",
                    (GCallback) action_pool_changed,
                    authority);

  priv->temporary_authorization_store = temporary_authorization_store_new (authority);

  priv->hash_scope_to_authentication_agent = g_hash_table_new_full ((GHashFunc) polkit_subject_hash,
                                                                    (GEqualFunc) polkit_subject_equal,
                                                                    (GDestroyNotify) g_object_unref,
                                                                    (GDestroyNotify) authentication_agent_unref);

  priv->session_monitor = polkit_backend_session_monitor_new ();
  g_signal_connect (priv->session_monitor,
                    "changed",
                    G_CALLBACK (on_session_monitor_changed),
                    authority);

  error = NULL;
  priv->system_bus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  if (priv->system_bus_connection == NULL)
    {
      g_warning ("Error getting system bus: %s", error->message);
      g_error_free (error);
    }
  else
    {
      /* TODO: this is a bit inefficient */
      priv->name_owner_changed_signal_id =
        g_dbus_connection_signal_subscribe (priv->system_bus_connection,
                                            "org.freedesktop.DBus",   /* sender */
                                            "org.freedesktop.DBus",   /* interface */
                                            "NameOwnerChanged",       /* member */
                                            "/org/freedesktop/DBus",  /* path */
                                            NULL,                     /* arg0 */
                                            G_DBUS_SIGNAL_FLAGS_NONE,
                                            on_name_owner_changed_signal,
                                            authority,
                                            NULL); /* GDestroyNotify */
    }
}

static void
polkit_backend_interactive_authority_finalize (GObject *object)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (object);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  if (priv->name_owner_changed_signal_id > 0)
    g_dbus_connection_signal_unsubscribe (priv->system_bus_connection, priv->name_owner_changed_signal_id);

  if (priv->system_bus_connection != NULL)
    g_object_unref (priv->system_bus_connection);

  if (priv->action_pool != NULL)
    g_object_unref (priv->action_pool);

  if (priv->session_monitor != NULL)
    g_object_unref (priv->session_monitor);

  temporary_authorization_store_free (priv->temporary_authorization_store);

  g_hash_table_unref (priv->hash_scope_to_authentication_agent);

  G_OBJECT_CLASS (polkit_backend_interactive_authority_parent_class)->finalize (object);
}

static const gchar *
polkit_backend_interactive_authority_get_name (PolkitBackendAuthority *authority)
{
  return "interactive";
}

static const gchar *
polkit_backend_interactive_authority_get_version (PolkitBackendAuthority *authority)
{
  return PACKAGE_VERSION;
}

static PolkitAuthorityFeatures
polkit_backend_interactive_authority_get_features (PolkitBackendAuthority *authority)
{
  return POLKIT_AUTHORITY_FEATURES_TEMPORARY_AUTHORIZATION;
}

static void
polkit_backend_interactive_authority_class_init (PolkitBackendInteractiveAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);

  gobject_class->finalize = polkit_backend_interactive_authority_finalize;

  authority_class->get_name                        = polkit_backend_interactive_authority_get_name;
  authority_class->get_version                     = polkit_backend_interactive_authority_get_version;
  authority_class->get_features                    = polkit_backend_interactive_authority_get_features;
  authority_class->enumerate_actions               = polkit_backend_interactive_authority_enumerate_actions;
  authority_class->check_authorization             = polkit_backend_interactive_authority_check_authorization;
  authority_class->check_authorization_finish      = polkit_backend_interactive_authority_check_authorization_finish;
  authority_class->register_authentication_agent   = polkit_backend_interactive_authority_register_authentication_agent;
  authority_class->unregister_authentication_agent = polkit_backend_interactive_authority_unregister_authentication_agent;
  authority_class->authentication_agent_response   = polkit_backend_interactive_authority_authentication_agent_response;
  authority_class->enumerate_temporary_authorizations = polkit_backend_interactive_authority_enumerate_temporary_authorizations;
  authority_class->revoke_temporary_authorizations = polkit_backend_interactive_authority_revoke_temporary_authorizations;
  authority_class->revoke_temporary_authorization_by_id = polkit_backend_interactive_authority_revoke_temporary_authorization_by_id;



  g_type_class_add_private (klass, sizeof (PolkitBackendInteractiveAuthorityPrivate));
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
polkit_backend_interactive_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                                  PolkitSubject            *caller,
                                                  const gchar              *interactivee,
                                                  GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GList *actions;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  actions = polkit_backend_action_pool_get_all_actions (priv->action_pool, interactivee);

  return actions;
}

/* ---------------------------------------------------------------------------------------------------- */

struct AuthenticationAgent
{
  volatile gint ref_count;

  uid_t creator_uid;
  PolkitSubject *scope;
  guint64 serial;

  gchar *locale;
  GVariant *registration_options;
  gchar *object_path;
  gchar *unique_system_bus_name;
  GRand *cookie_pool;
  gchar *cookie_prefix;
  guint64  cookie_serial;

  GDBusProxy *proxy;

  GList *active_sessions;
};

/* TODO: should probably move to PolkitSubject
 * (also see copy in src/programs/pkcheck.c)
 *
 * Also, can't really trust the cmdline... but might be useful in the logs anyway.
 */
static gchar *
_polkit_subject_get_cmdline (PolkitSubject *subject)
{
  PolkitSubject *process;
  gchar *ret;
  gint pid;
  gchar *filename;
  gchar *contents;
  gsize contents_len;
  GError *error;
  guint n;

  g_return_val_if_fail (subject != NULL, NULL);

  error = NULL;

  ret = NULL;
  process = NULL;
  filename = NULL;
  contents = NULL;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      process = g_object_ref (subject);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                         NULL,
                                                         &error);
      if (process == NULL)
        {
          g_printerr ("Error getting process for system bus name `%s': %s\n",
                      polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                      error->message);
          g_error_free (error);
          goto out;
        }
    }
  else
    {
      g_warning ("Unknown subject type passed to _polkit_subject_get_cmdline()");
      goto out;
    }

  pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));

  filename = g_strdup_printf ("/proc/%d/cmdline", pid);

  if (!g_file_get_contents (filename,
                            &contents,
                            &contents_len,
                            &error))
    {
      g_printerr ("Error opening `%s': %s\n",
                  filename,
                  error->message);
      g_error_free (error);
      goto out;
    }

  if (contents == NULL || contents_len == 0)
    {
      goto out;
    }
  else
    {
      /* The kernel uses '\0' to separate arguments - replace those with a space. */
      for (n = 0; n < contents_len - 1; n++)
        {
          if (contents[n] == '\0')
            contents[n] = ' ';
        }
      ret = g_strdup (contents);
      g_strstrip (ret);
    }

 out:
  g_free (filename);
  g_free (contents);
  if (process != NULL)
    g_object_unref (process);
  return ret;
}

/* TODO: possibly remove this function altogether */
G_GNUC_UNUSED static void
log_result (PolkitBackendInteractiveAuthority    *authority,
            const gchar                          *action_id,
            PolkitSubject                        *subject,
            PolkitSubject                        *caller,
            PolkitAuthorizationResult            *result)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitIdentity *user_of_subject;
  const gchar *log_result_str;
  gchar *subject_str;
  gchar *user_of_subject_str;
  gchar *caller_str;
  gchar *subject_cmdline;
  gchar *caller_cmdline;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  log_result_str = "DENYING";
  if (polkit_authorization_result_get_is_authorized (result))
    log_result_str = "ALLOWING";

  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor, subject, NULL, NULL);

  subject_str = polkit_subject_to_string (subject);

  if (user_of_subject != NULL)
    user_of_subject_str = polkit_identity_to_string (user_of_subject);
  else
    user_of_subject_str = g_strdup ("<unknown>");
  caller_str = polkit_subject_to_string (caller);

  subject_cmdline = _polkit_subject_get_cmdline (subject);
  if (subject_cmdline == NULL)
    subject_cmdline = g_strdup ("<unknown>");

  caller_cmdline = _polkit_subject_get_cmdline (caller);
  if (caller_cmdline == NULL)
    caller_cmdline = g_strdup ("<unknown>");

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "%s action %s for %s [%s] owned by %s (check requested by %s [%s])",
                                log_result_str,
                                action_id,
                                subject_str,
                                subject_cmdline,
                                user_of_subject_str,
                                caller_str,
                                caller_cmdline);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);
  g_free (subject_str);
  g_free (user_of_subject_str);
  g_free (caller_str);
  g_free (subject_cmdline);
  g_free (caller_cmdline);
}

static void
check_authorization_challenge_cb (AuthenticationAgent         *agent,
                                  PolkitSubject               *subject,
                                  PolkitIdentity              *user_of_subject,
                                  PolkitSubject               *caller,
                                  PolkitBackendInteractiveAuthority *authority,
                                  const gchar                 *action_id,
                                  PolkitDetails               *details,
                                  PolkitImplicitAuthorization  implicit_authorization,
                                  gboolean                     authentication_success,
                                  gboolean                     was_dismissed,
                                  PolkitIdentity              *authenticated_identity,
                                  gpointer                     user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitAuthorizationResult *result;
  gchar *scope_str;
  gchar *subject_str;
  gchar *user_of_subject_str;
  gchar *authenticated_identity_str;
  gchar *subject_cmdline;
  gboolean is_temp;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  result = NULL;

  scope_str = polkit_subject_to_string (agent->scope);
  subject_str = polkit_subject_to_string (subject);
  user_of_subject_str = polkit_identity_to_string (user_of_subject);
  authenticated_identity_str = NULL;
  if (authenticated_identity != NULL)
    authenticated_identity_str = polkit_identity_to_string (authenticated_identity);

  subject_cmdline = _polkit_subject_get_cmdline (subject);
  if (subject_cmdline == NULL)
    subject_cmdline = g_strdup ("<unknown>");

  g_debug ("In check_authorization_challenge_cb\n"
           "  subject                %s\n"
           "  action_id              %s\n"
           "  was_dismissed          %d\n"
           "  authentication_success %d\n",
           subject_str,
           action_id,
           was_dismissed,
           authentication_success);

  if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED ||
      implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
    polkit_details_insert (details, "polkit.retains_authorization_after_challenge", "true");

  is_temp = FALSE;
  if (authentication_success)
    {
      /* store temporary authorization depending on value of implicit_authorization */
      if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED ||
          implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
        {
          const gchar *id;

          is_temp = TRUE;

          id = temporary_authorization_store_add_authorization (priv->temporary_authorization_store,
                                                                subject,
                                                                authentication_agent_get_scope (agent),
                                                                action_id);

          polkit_details_insert (details, "polkit.temporary_authorization_id", id);

          /* we've added a temporary authorization, let the user know */
          g_signal_emit_by_name (authority, "changed");
        }
      result = polkit_authorization_result_new (TRUE, FALSE, details);
    }
  else
    {
      /* TODO: maybe return set is_challenge? */
      if (was_dismissed)
        polkit_details_insert (details, "polkit.dismissed", "true");
      result = polkit_authorization_result_new (FALSE, FALSE, details);
    }

  /* Log the event */
  if (authentication_success)
    {
      if (is_temp)
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Operator of %s successfully authenticated as %s to gain "
                                        "TEMPORARY authorization for action %s for %s [%s] (owned by %s)",
                                        scope_str,
                                        authenticated_identity_str,
                                        action_id,
                                        subject_str,
                                        subject_cmdline,
                                        user_of_subject_str);
        }
      else
        {
          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Operator of %s successfully authenticated as %s to gain "
                                        "ONE-SHOT authorization for action %s for %s [%s] (owned by %s)",
                                        scope_str,
                                        authenticated_identity_str,
                                        action_id,
                                        subject_str,
                                        subject_cmdline,
                                        user_of_subject_str);
        }
    }
  else
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Operator of %s FAILED to authenticate to gain "
                                    "authorization for action %s for %s [%s] (owned by %s)",
                                    scope_str,
                                    action_id,
                                    subject_str,
                                    subject_cmdline,
                                    user_of_subject_str);
    }

  /* log_result (authority, action_id, subject, caller, result); */

  g_simple_async_result_set_op_res_gpointer (simple,
                                             result,
                                             g_object_unref);
  g_simple_async_result_complete (simple);
  g_object_unref (simple);

  g_free (subject_cmdline);
  g_free (authenticated_identity_str);
  g_free (user_of_subject_str);
  g_free (subject_str);
  g_free (scope_str);
}

static PolkitAuthorizationResult *
polkit_backend_interactive_authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                                                 GAsyncResult            *res,
                                                                 GError                 **error)
{
  GSimpleAsyncResult *simple;
  PolkitAuthorizationResult *result;

  simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_backend_interactive_authority_check_authorization);

  result = NULL;

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

  result = g_object_ref (g_simple_async_result_get_op_res_gpointer (simple));

 out:
  return result;
}

static gboolean
may_identity_check_authorization (PolkitBackendInteractiveAuthority   *interactive_authority,
                                  const gchar                         *action_id,
                                  PolkitIdentity                      *identity)
{
  PolkitBackendInteractiveAuthorityPrivate *priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);
  gboolean ret = FALSE;
  PolkitActionDescription *action_desc = NULL;
  const gchar *owners = NULL;
  gchar **tokens = NULL;
  guint n;

  /* uid 0 may check anything */
  if (identity_is_root_user (identity))
    {
      ret = TRUE;
      goto out;
    }

  action_desc = polkit_backend_action_pool_get_action (priv->action_pool, action_id, NULL);
  if (action_desc == NULL)
    goto out;

  owners = polkit_action_description_get_annotation (action_desc, "org.freedesktop.policykit.owner");
  if (owners == NULL)
    goto out;

  tokens = g_strsplit (owners, " ", 0);
  for (n = 0; tokens != NULL && tokens[n] != NULL; n++)
    {
      PolkitIdentity *owner_identity;
      GError *error = NULL;
      owner_identity = polkit_identity_from_string (tokens[n], &error);
      if (owner_identity == NULL)
        {
          g_warning ("Error parsing owner identity %d of action_id %s: %s (%s, %d)",
                     n, action_id, error->message, g_quark_to_string (error->domain), error->code);
          g_error_free (error);
          continue;
        }
      if (polkit_identity_equal (identity, owner_identity))
        {
          ret = TRUE;
          g_object_unref (owner_identity);
          goto out;
        }
      g_object_unref (owner_identity);
    }

 out:
  g_clear_object (&action_desc);
  g_strfreev (tokens);

  return ret;
}

static void
polkit_backend_interactive_authority_check_authorization (PolkitBackendAuthority         *authority,
                                                          PolkitSubject                  *caller,
                                                          PolkitSubject                  *subject,
                                                          const gchar                    *action_id,
                                                          PolkitDetails                  *details,
                                                          PolkitCheckAuthorizationFlags   flags,
                                                          GCancellable                   *cancellable,
                                                          GAsyncReadyCallback             callback,
                                                          gpointer                        user_data)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  gchar *caller_str;
  gchar *subject_str;
  PolkitIdentity *user_of_caller;
  PolkitIdentity *user_of_subject;
  gboolean user_of_subject_matches;
  gchar *user_of_caller_str;
  gchar *user_of_subject_str;
  PolkitAuthorizationResult *result;
  PolkitImplicitAuthorization implicit_authorization;
  GError *error;
  GSimpleAsyncResult *simple;
  gboolean has_details;
  gchar **detail_keys;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  error = NULL;
  caller_str = NULL;
  subject_str = NULL;
  user_of_caller = NULL;
  user_of_subject = NULL;
  user_of_caller_str = NULL;
  user_of_subject_str = NULL;
  result = NULL;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_backend_interactive_authority_check_authorization);

  /* handle being called from ourselves */
  if (caller == NULL)
    {
      /* TODO: this is kind of a hack */
      GDBusConnection *system_bus;
      system_bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, NULL);
      caller = polkit_system_bus_name_new (g_dbus_connection_get_unique_name (system_bus));
      g_object_unref (system_bus);
    }

  caller_str = polkit_subject_to_string (caller);
  subject_str = polkit_subject_to_string (subject);

  g_debug ("%s is inquiring whether %s is authorized for %s",
           caller_str,
           subject_str,
           action_id);

  user_of_caller = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                        caller, NULL,
                                                                        &error);
  if (error != NULL)
    {
      g_simple_async_result_set_from_error (simple, error);
      g_simple_async_result_complete (simple);
      g_object_unref (simple);
      g_error_free (error);
      goto out;
    }

  user_of_caller_str = polkit_identity_to_string (user_of_caller);
  g_debug (" user of caller is %s", user_of_caller_str);

  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject, &user_of_subject_matches,
                                                                         &error);
  if (error != NULL)
    {
      g_simple_async_result_set_from_error (simple, error);
      g_simple_async_result_complete (simple);
      g_object_unref (simple);
      g_error_free (error);
      goto out;
    }

  user_of_subject_str = polkit_identity_to_string (user_of_subject);
  g_debug (" user of subject is %s", user_of_subject_str);

  has_details = FALSE;
  if (details != NULL)
    {
      detail_keys = polkit_details_get_keys (details);
      if (detail_keys != NULL)
        {
          if (g_strv_length (detail_keys) > 0)
            has_details = TRUE;
          g_strfreev (detail_keys);
        }
    }

  /* Not anyone is allowed to check that process XYZ is allowed to do ABC.
   * We allow this if, and only if,
   *
   *  - processes may check for another process owned by the *same* user but not
   *    if details are passed (otherwise you'd be able to spoof the dialog);
   *    the caller supplies the user_of_subject value, so we additionally
   *    require it to match at least at one point in time (via
   *    user_of_subject_matches).
   *
   *  - processes running as uid 0 may check anything and pass any details
   *
   *  - if the action_id has the "org.freedesktop.policykit.owner" annotation
   *    then any uid referenced by that annotation is also allowed to check
   *    anything and pass any details
   */
  if (!user_of_subject_matches
      || !polkit_identity_equal (user_of_caller, user_of_subject)
      || has_details)
    {
      if (!may_identity_check_authorization (interactive_authority, action_id, user_of_caller))
        {
          if (has_details)
            {
              g_simple_async_result_set_error (simple,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_NOT_AUTHORIZED,
                                               "Only trusted callers (e.g. uid 0 or an action owner) can use CheckAuthorization() and "
                                               "pass details");
            }
          else
            {
              g_simple_async_result_set_error (simple,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_NOT_AUTHORIZED,
                                               "Only trusted callers (e.g. uid 0 or an action owner) can use CheckAuthorization() for "
                                               "subjects belonging to other identities");
            }
          g_simple_async_result_complete (simple);
          g_object_unref (simple);
          goto out;
        }
    }

  implicit_authorization = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
  result = check_authorization_sync (authority,
                                     caller,
                                     subject,
                                     action_id,
                                     details,
                                     flags,
                                     &implicit_authorization,
                                     FALSE, /* checking_imply */
                                     &error);
  if (error != NULL)
    {
      g_simple_async_result_set_from_error (simple, error);
      g_simple_async_result_complete (simple);
      g_object_unref (simple);
      g_error_free (error);
      goto out;
    }

  /* Caller is up for a challenge! With light sabers! Use an authentication agent if one exists... */
  if (polkit_authorization_result_get_is_challenge (result) &&
      (flags & POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION))
    {
      AuthenticationAgent *agent;

      agent = get_authentication_agent_for_subject (interactive_authority, subject);
      if (agent != NULL)
        {
          g_object_unref (result);
          result = NULL;

          g_debug (" using authentication agent for challenge");

          authentication_agent_initiate_challenge (agent,
                                                   subject,
                                                   user_of_subject,
                                                   interactive_authority,
                                                   action_id,
                                                   details,
                                                   caller,
                                                   implicit_authorization,
                                                   cancellable,
                                                   check_authorization_challenge_cb,
                                                   simple);

          /* keep going */
          goto out;
        }
    }

  /* log_result (interactive_authority, action_id, subject, caller, result); */

  /* Otherwise just return the result */
  g_simple_async_result_set_op_res_gpointer (simple,
                                             g_object_ref (result),
                                             g_object_unref);
  g_simple_async_result_complete (simple);
  g_object_unref (simple);

 out:

  if (user_of_caller != NULL)
    g_object_unref (user_of_caller);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);

  g_free (caller_str);
  g_free (subject_str);
  g_free (user_of_caller_str);
  g_free (user_of_subject_str);

  if (result != NULL)
    g_object_unref (result);
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitAuthorizationResult *
check_authorization_sync (PolkitBackendAuthority         *authority,
                          PolkitSubject                  *caller,
                          PolkitSubject                  *subject,
                          const gchar                    *action_id,
                          PolkitDetails                  *details,
                          PolkitCheckAuthorizationFlags   flags,
                          PolkitImplicitAuthorization    *out_implicit_authorization,
                          gboolean                        checking_imply,
                          GError                        **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitAuthorizationResult *result;
  PolkitIdentity *user_of_subject;
  PolkitSubject *session_for_subject;
  gchar *subject_str;
  GList *groups_of_user;
  PolkitActionDescription *action_desc;
  gboolean session_is_local;
  gboolean session_is_active;
  PolkitImplicitAuthorization implicit_authorization;
  const gchar *tmp_authz_id;
  GList *actions;
  GList *l;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  result = NULL;

  actions = NULL;
  user_of_subject = NULL;
  groups_of_user = NULL;
  subject_str = NULL;
  session_for_subject = NULL;

  session_is_local = FALSE;
  session_is_active = FALSE;

  subject_str = polkit_subject_to_string (subject);

  g_debug ("checking whether %s is authorized for %s",
           subject_str,
           action_id);

  /* get the action description */
  action_desc = polkit_backend_action_pool_get_action (priv->action_pool,
                                                       action_id,
                                                       NULL);

  if (action_desc == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Action %s is not registered",
                   action_id);
      goto out;
    }

  /* every subject has a user; this is supplied by the client, so we rely
   * on the caller to validate its acceptability. */
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject, NULL,
                                                                         error);
  if (user_of_subject == NULL)
      goto out;

  /* special case: uid 0, root, is _always_ authorized for anything */
  if (identity_is_root_user (user_of_subject))
    {
      result = polkit_authorization_result_new (TRUE, FALSE, NULL);
      goto out;
    }

  /* a subject *may* be in a session */
  session_for_subject = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                                subject,
                                                                                NULL);
  g_debug ("  %p", session_for_subject);
  if (session_for_subject != NULL)
    {
      session_is_local = polkit_backend_session_monitor_is_session_local (priv->session_monitor, session_for_subject);
      session_is_active = polkit_backend_session_monitor_is_session_active (priv->session_monitor, session_for_subject);

      g_debug (" subject is in session %s (local=%d active=%d)",
               polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session_for_subject)),
               session_is_local,
               session_is_active);
    }

  /* find the implicit authorization to use; it depends on is_local and is_active */
  if (session_is_local)
    {
      if (session_is_active)
        implicit_authorization = polkit_action_description_get_implicit_active (action_desc);
      else
        implicit_authorization = polkit_action_description_get_implicit_inactive (action_desc);
    }
  else
    {
      implicit_authorization = polkit_action_description_get_implicit_any (action_desc);
    }

  /* allow subclasses to rewrite implicit_authorization */
  implicit_authorization = polkit_backend_interactive_authority_check_authorization_sync (interactive_authority,
                                                                                          caller,
                                                                                          subject,
                                                                                          user_of_subject,
                                                                                          session_is_local,
                                                                                          session_is_active,
                                                                                          action_id,
                                                                                          details,
                                                                                          implicit_authorization);
  /* first see if there's an implicit authorization for subject available */
  if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED)
    {
      g_debug (" is authorized (has implicit authorization local=%d active=%d)",
               session_is_local,
               session_is_active);
      result = polkit_authorization_result_new (TRUE, FALSE, details);
      goto out;
    }

  /* then see if there's a temporary authorization for the subject */
  if (temporary_authorization_store_has_authorization (priv->temporary_authorization_store,
                                                       subject,
                                                       action_id,
                                                       &tmp_authz_id))
    {

      g_debug (" is authorized (has temporary authorization)");
      polkit_details_insert (details, "polkit.temporary_authorization_id", tmp_authz_id);
      result = polkit_authorization_result_new (TRUE, FALSE, details);
      goto out;
    }

  /* then see if implied by another action that the subject is authorized for
   * (but only one level deep to avoid infinite recursion)
   *
   * TODO: if this is slow, we can maintain a hash table for looking up what
   * actions implies a given action
   */
  if (!checking_imply)
    {
      actions = polkit_backend_action_pool_get_all_actions (priv->action_pool, NULL);
      for (l = actions; l != NULL; l = l->next)
        {
          PolkitActionDescription *imply_ad = POLKIT_ACTION_DESCRIPTION (l->data);
          const gchar *imply;
          imply = polkit_action_description_get_annotation (imply_ad, "org.freedesktop.policykit.imply");
          if (imply != NULL)
            {
              gchar **tokens;
              guint n;
              tokens = g_strsplit (imply, " ", 0);
              for (n = 0; tokens[n] != NULL; n++)
                {
                  if (g_strcmp0 (tokens[n], action_id) == 0)
                    {
                      PolkitAuthorizationResult *implied_result = NULL;
                      PolkitImplicitAuthorization implied_implicit_authorization;
                      GError *implied_error = NULL;
                      const gchar *imply_action_id;

                      imply_action_id = polkit_action_description_get_action_id (imply_ad);

                      /* g_debug ("%s is implied by %s, checking", action_id, imply_action_id); */
                      implied_result = check_authorization_sync (authority, caller, subject,
                                                                 imply_action_id,
                                                                 details, flags,
                                                                 &implied_implicit_authorization, TRUE,
                                                                 &implied_error);
                      if (implied_result != NULL)
                        {
                          if (polkit_authorization_result_get_is_authorized (implied_result))
                            {
                              g_debug (" is authorized (implied by %s)", imply_action_id);
                              result = implied_result;
                              /* cleanup */
                              g_strfreev (tokens);
                              goto out;
                            }
                          g_object_unref (implied_result);
                        }
                      if (implied_error != NULL)
                        g_error_free (implied_error);
                    }
                }
              g_strfreev (tokens);
            }
        }
    }

  if (implicit_authorization != POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED)
    {
      if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED ||
          implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
        {
          polkit_details_insert (details, "polkit.retains_authorization_after_challenge", "1");
        }

      result = polkit_authorization_result_new (FALSE, TRUE, details);

      /* return implicit_authorization so the caller can use an authentication agent if applicable */
      if (out_implicit_authorization != NULL)
        *out_implicit_authorization = implicit_authorization;

      g_debug (" challenge (implicit_authorization = %s)",
               polkit_implicit_authorization_to_string (implicit_authorization));
    }
  else
    {
      result = polkit_authorization_result_new (FALSE, FALSE, details);
      g_debug (" not authorized");
    }
 out:
  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  g_free (subject_str);

  g_list_foreach (groups_of_user, (GFunc) g_object_unref, NULL);
  g_list_free (groups_of_user);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);

  if (session_for_subject != NULL)
    g_object_unref (session_for_subject);

  if (action_desc != NULL)
    g_object_unref (action_desc);

  g_debug (" ");

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_backend_interactive_authority_get_admin_identities:
 * @authority: A #PolkitBackendInteractiveAuthority.
 * @caller: The subject that is inquiring whether @subject is authorized.
 * @subject: The subject we are about to authenticate for.
 * @user_for_subject: The user of the subject we are about to authenticate for.
 * @subject_is_local: %TRUE if the session for @subject is local.
 * @subject_is_active: %TRUE if the session for @subject is active.
 * @action_id: The action we are about to authenticate for.
 * @details: Details about the action.
 *
 * Gets a list of identities to use for administrator authentication.
 *
 * The default implementation returns a list with a single element for the super user.
 *
 * Returns: A list of #PolkitIdentity objects. Free each element
 *     g_object_unref(), then free the list with g_list_free().
 */
GList *
polkit_backend_interactive_authority_get_admin_identities (PolkitBackendInteractiveAuthority *authority,
                                                           PolkitSubject                     *caller,
                                                           PolkitSubject                     *subject,
                                                           PolkitIdentity                    *user_for_subject,
                                                           gboolean                           subject_is_local,
                                                           gboolean                           subject_is_active,
                                                           const gchar                       *action_id,
                                                           PolkitDetails                     *details)
{
  PolkitBackendInteractiveAuthorityClass *klass;
  GList *ret = NULL;

  klass = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_CLASS (authority);

  if (klass->get_admin_identities != NULL)
    {
      ret = klass->get_admin_identities (authority,
                                         caller,
                                         subject,
                                         user_for_subject,
                                         subject_is_local,
                                         subject_is_active,
                                         action_id,
                                         details);
    }

  return ret;
}

/**
 * polkit_backend_interactive_authority_check_authorization_sync:
 * @authority: A #PolkitBackendInteractiveAuthority.
 * @caller: The subject that is inquiring whether @subject is authorized.
 * @subject: The subject we are checking an authorization for.
 * @user_for_subject: The user of the subject we are checking an authorization for.
 * @subject_is_local: %TRUE if the session for @subject is local.
 * @subject_is_active: %TRUE if the session for @subject is active.
 * @action_id: The action we are checking an authorization for.
 * @details: Details about the action.
 * @implicit: A #PolkitImplicitAuthorization value computed from the policy file and @subject.
 *
 * Checks whether @subject is authorized to perform the action
 * specified by @action_id and @details. The implementation may append
 * key/value pairs to @details to return extra information to @caller.
 *
 * The default implementation of this method simply returns @implicit.
 *
 * Returns: A #PolkitImplicitAuthorization that specifies if the subject is authorized or whether
 *     authentication is required.
 */
PolkitImplicitAuthorization
polkit_backend_interactive_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *authority,
                                                               PolkitSubject                     *caller,
                                                               PolkitSubject                     *subject,
                                                               PolkitIdentity                    *user_for_subject,
                                                               gboolean                           subject_is_local,
                                                               gboolean                           subject_is_active,
                                                               const gchar                       *action_id,
                                                               PolkitDetails                     *details,
                                                               PolkitImplicitAuthorization        implicit)
{
  PolkitBackendInteractiveAuthorityClass *klass;
  PolkitImplicitAuthorization ret;

  klass = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_CLASS (authority);

  if (klass->check_authorization_sync == NULL)
    {
      ret = implicit;
    }
  else
    {
      ret = klass->check_authorization_sync (authority,
                                             caller,
                                             subject,
                                             user_for_subject,
                                             subject_is_local,
                                             subject_is_active,
                                             action_id,
                                             details,
                                             implicit);
    }

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

struct AuthenticationSession
{
  AuthenticationAgent         *agent;

  gchar                       *cookie;

  PolkitSubject               *subject;

  PolkitIdentity              *user_of_subject;

  PolkitSubject               *caller;

  PolkitBackendInteractiveAuthority *authority;

  GList                       *identities;

  gchar                       *action_id;

  PolkitDetails               *details;

  gchar                       *initiated_by_system_bus_unique_name;

  PolkitImplicitAuthorization  implicit_authorization;

  AuthenticationAgentCallback  callback;

  gpointer                     user_data;

  guint                        call_id;

  gboolean                     is_authenticated;
  PolkitIdentity              *authenticated_identity;

  GCancellable                *cancellable;

  gulong                       cancellable_signal_handler_id;
};

static void
authentication_session_cancelled_cb (GCancellable *cancellable,
                                     AuthenticationSession *session)
{
  authentication_session_cancel (session);
}

/* We're not calling this a UUID, but it's basically
 * the same thing, just not formatted that way because:
 *
 *  - I'm too lazy to do it
 *  - If we did, people might think it was actually
 *    generated from /dev/random, which we're not doing
 *    because this value doesn't actually need to be
 *    globally unique.
 */
static void
append_rand_u128_str (GString *buf,
                      GRand   *pool)
{
  g_string_append_printf (buf, "%08x%08x%08x%08x",
                          g_rand_int (pool),
                          g_rand_int (pool),
                          g_rand_int (pool),
                          g_rand_int (pool));
}

/* A value that should be unique to the (AuthenticationAgent, AuthenticationSession)
 * pair, and not guessable by other agents.
 *
 * <agent serial> - <agent uuid> - <session serial> - <session uuid>
 *
 * See http://lists.freedesktop.org/archives/polkit-devel/2015-June/000425.html
 *
 */
static gchar *
authentication_agent_generate_cookie (AuthenticationAgent *agent)
{
  GString *buf = g_string_new ("");

  g_string_append (buf, agent->cookie_prefix);
  
  g_string_append_c (buf, '-');
  agent->cookie_serial++;
  g_string_append_printf (buf, "%" G_GUINT64_FORMAT, 
                          agent->cookie_serial);
  g_string_append_c (buf, '-');
  append_rand_u128_str (buf, agent->cookie_pool);

  return g_string_free (buf, FALSE);
}


static AuthenticationSession *
authentication_session_new (AuthenticationAgent         *agent,
                            PolkitSubject               *subject,
                            PolkitIdentity              *user_of_subject,
                            PolkitSubject               *caller,
                            PolkitBackendInteractiveAuthority *authority,
                            GList                       *identities,
                            const gchar                 *action_id,
                            PolkitDetails               *details,
                            const gchar                 *initiated_by_system_bus_unique_name,
                            PolkitImplicitAuthorization  implicit_authorization,
                            GCancellable                *cancellable,
                            AuthenticationAgentCallback  callback,
                            gpointer                     user_data)
{
  AuthenticationSession *session;

  session = g_new0 (AuthenticationSession, 1);
  session->agent = authentication_agent_ref (agent);
  session->cookie = authentication_agent_generate_cookie (agent);
  session->subject = g_object_ref (subject);
  session->user_of_subject = g_object_ref (user_of_subject);
  session->caller = g_object_ref (caller);
  session->authority = g_object_ref (authority);
  session->identities = g_list_copy (identities);
  g_list_foreach (session->identities, (GFunc) g_object_ref, NULL);
  session->action_id = g_strdup (action_id);
  session->details = g_object_ref (details);
  session->initiated_by_system_bus_unique_name = g_strdup (initiated_by_system_bus_unique_name);
  session->implicit_authorization = implicit_authorization;
  session->cancellable = cancellable != NULL ? g_object_ref (cancellable) : NULL;
  session->callback = callback;
  session->user_data = user_data;

  if (session->cancellable != NULL)
    {
      session->cancellable_signal_handler_id = g_signal_connect (session->cancellable,
                                                                 "cancelled",
                                                                 G_CALLBACK (authentication_session_cancelled_cb),
                                                                 session);
    }

  return session;
}

static void
authentication_session_free (AuthenticationSession *session)
{
  authentication_agent_unref (session->agent);
  g_free (session->cookie);
  g_list_foreach (session->identities, (GFunc) g_object_unref, NULL);
  g_list_free (session->identities);
  g_object_unref (session->subject);
  g_object_unref (session->user_of_subject);
  g_object_unref (session->caller);
  g_object_unref (session->authority);
  g_free (session->action_id);
  g_object_unref (session->details);
  g_free (session->initiated_by_system_bus_unique_name);
  if (session->cancellable_signal_handler_id > 0)
    g_signal_handler_disconnect (session->cancellable, session->cancellable_signal_handler_id);
  if (session->authenticated_identity != NULL)
    g_object_unref (session->authenticated_identity);
  if (session->cancellable != NULL)
    g_object_unref (session->cancellable);
  g_free (session);
}

static PolkitSubject *
authentication_agent_get_scope (AuthenticationAgent *agent)
{
  return agent->scope;
}

static void
authentication_agent_cancel_all_sessions (AuthenticationAgent *agent)
{
  /* cancel all active authentication sessions; use a copy of the list since
   * callbacks will modify the list
   */
  if (agent->active_sessions != NULL)
    {
      GList *l;
      GList *active_sessions;

      active_sessions = g_list_copy (agent->active_sessions);
      for (l = active_sessions; l != NULL; l = l->next)
        {
          AuthenticationSession *session = l->data;
          authentication_session_cancel (session);
        }
      g_list_free (active_sessions);
    }
}

static AuthenticationAgent *
authentication_agent_ref (AuthenticationAgent *agent)
{
  g_atomic_int_inc (&agent->ref_count);
  return agent;
}

static void
authentication_agent_unref (AuthenticationAgent *agent)
{
  if (g_atomic_int_dec_and_test (&agent->ref_count))
    {
      if (agent->proxy != NULL)
        g_object_unref (agent->proxy);
      g_object_unref (agent->scope);
      g_free (agent->locale);
      g_free (agent->object_path);
      g_free (agent->unique_system_bus_name);
      if (agent->registration_options != NULL)
        g_variant_unref (agent->registration_options);
      g_rand_free (agent->cookie_pool);
      g_free (agent->cookie_prefix);
      g_free (agent);
    }
}

static AuthenticationAgent *
authentication_agent_new (guint64      serial,
                          PolkitSubject *scope,
                          PolkitIdentity *creator,
                          const gchar *unique_system_bus_name,
                          const gchar *locale,
                          const gchar *object_path,
                          GVariant    *registration_options,
                          GError     **error)
{
  AuthenticationAgent *agent;
  GDBusProxy *proxy;
  PolkitUnixUser *creator_user;

  g_assert (POLKIT_IS_UNIX_USER (creator));
  creator_user = POLKIT_UNIX_USER (creator);

  if (!g_variant_is_object_path (object_path))
    {
      g_set_error (error, POLKIT_ERROR, POLKIT_ERROR_FAILED,
                   "Invalid object path '%s'", object_path);
      return NULL;
    }

  proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                         G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
                                         G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                                         NULL, /* GDBusInterfaceInfo* */
                                         unique_system_bus_name,
                                         object_path,
                                         "org.freedesktop.PolicyKit1.AuthenticationAgent",
                                         NULL, /* GCancellable* */
                                         error);
  if (proxy == NULL)
    {
      g_prefix_error (error, "Failed to construct proxy for agent: " );
      return NULL;
    }

  agent = g_new0 (AuthenticationAgent, 1);
  agent->ref_count = 1;
  agent->serial = serial;
  agent->scope = g_object_ref (scope);
  agent->creator_uid = (uid_t)polkit_unix_user_get_uid (creator_user);
  agent->object_path = g_strdup (object_path);
  agent->unique_system_bus_name = g_strdup (unique_system_bus_name);
  agent->locale = g_strdup (locale);
  agent->registration_options = registration_options != NULL ? g_variant_ref (registration_options) : NULL;
  agent->proxy = proxy;

  {
    GString *cookie_prefix = g_string_new ("");
    GRand *agent_private_rand = g_rand_new ();

    g_string_append_printf (cookie_prefix, "%" G_GUINT64_FORMAT "-", agent->serial);

    /* Use a uniquely seeded PRNG to get a prefix cookie for this agent,
     * whose sequence will not correlate with the per-authentication session
     * cookies.
     */
    append_rand_u128_str (cookie_prefix, agent_private_rand);
    g_rand_free (agent_private_rand);

    agent->cookie_prefix = g_string_free (cookie_prefix, FALSE);
    
    /* And a newly seeded pool for per-session cookies */
    agent->cookie_pool = g_rand_new ();
  }

  return agent;
}

static AuthenticationAgent *
get_authentication_agent_for_subject (PolkitBackendInteractiveAuthority *authority,
                                      PolkitSubject *subject)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_subject = NULL;
  AuthenticationAgent *agent = NULL;
  AuthenticationAgent *agent_fallback = NULL;
  gboolean fallback = FALSE;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  agent = g_hash_table_lookup (priv->hash_scope_to_authentication_agent, subject);

  if (agent == NULL && POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      PolkitSubject *process;
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                         NULL,
                                                         NULL);
      if (process != NULL)
        {
          agent = g_hash_table_lookup (priv->hash_scope_to_authentication_agent, process);
          g_object_unref (process);
        }
    }

  if (agent != NULL)
    {
      /* We have an agent! Now see if we should use this as a fallback only */
      if (agent->registration_options != NULL &&
          g_variant_lookup (agent->registration_options, "fallback", "b", &fallback) &&
          fallback)
        {
          agent_fallback = agent;
          agent = NULL;
        }
      else
        {
          /* Nope, use it */
          goto out;
        }
    }

  /* Now, we should also cover the case where @subject is a
   * UnixProcess but the agent is a SystemBusName. However, this can't
   * happen because we only allow registering agents for UnixProcess
   * and UnixSession subjects!
   */

  session_for_subject = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                                subject,
                                                                                NULL);
  if (session_for_subject == NULL)
    goto out;

  agent = g_hash_table_lookup (priv->hash_scope_to_authentication_agent, session_for_subject);

  /* use fallback, if available */
  if (agent == NULL && agent_fallback != NULL)
    agent = agent_fallback;

 out:
  if (session_for_subject != NULL)
    g_object_unref (session_for_subject);

  return agent;
}

static AuthenticationSession *
get_authentication_session_for_uid_and_cookie (PolkitBackendInteractiveAuthority *authority,
                                               uid_t                              uid,
                                               const gchar                       *cookie)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GHashTableIter hash_iter;
  AuthenticationAgent *agent;
  AuthenticationSession *result;

  result = NULL;

  /* TODO: perhaps use a hash on the cookie to speed this up */

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  g_hash_table_iter_init (&hash_iter, priv->hash_scope_to_authentication_agent);
  while (g_hash_table_iter_next (&hash_iter, NULL, (gpointer) &agent))
    {
      GList *l;

      /* We need to ensure that if somehow we have duplicate cookies
       * due to wrapping, that the cookie used is matched to the user
       * who called AuthenticationAgentResponse2.  See
       * http://lists.freedesktop.org/archives/polkit-devel/2015-June/000425.html
       * 
       * Except if the legacy AuthenticationAgentResponse is invoked,
       * we don't know the uid and hence use -1.  Continue to support
       * the old behavior for backwards compatibility, although everyone
       * who is using our own setuid helper will automatically be updated
       * to the new API.
       */
      if (uid != (uid_t)-1)
        {
          if (agent->creator_uid != uid)
            continue;
        }

      for (l = agent->active_sessions; l != NULL; l = l->next)
        {
          AuthenticationSession *session = l->data;

          if (strcmp (session->cookie, cookie) == 0)
            {
              result = session;
              goto out;
            }
        }
    }

 out:
  return result;
}

static GList *
get_authentication_sessions_initiated_by_system_bus_unique_name (PolkitBackendInteractiveAuthority *authority,
                                                                 const gchar *system_bus_unique_name)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GHashTableIter hash_iter;
  AuthenticationAgent *agent;
  GList *result;

  result = NULL;

  /* TODO: perhaps use a hash on the cookie to speed this up */

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  g_hash_table_iter_init (&hash_iter, priv->hash_scope_to_authentication_agent);
  while (g_hash_table_iter_next (&hash_iter, NULL, (gpointer) &agent))
    {
      GList *l;

      for (l = agent->active_sessions; l != NULL; l = l->next)
        {
          AuthenticationSession *session = l->data;

          if (strcmp (session->initiated_by_system_bus_unique_name, system_bus_unique_name) == 0)
            {
              result = g_list_prepend (result, session);
            }
        }
    }

   return result;
}

static GList *
get_authentication_sessions_for_system_bus_unique_name_subject (PolkitBackendInteractiveAuthority *authority,
                                                                const gchar *system_bus_unique_name)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GHashTableIter hash_iter;
  AuthenticationAgent *agent;
  GList *result;

  result = NULL;

  /* TODO: perhaps use a hash on the cookie to speed this up */

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  g_hash_table_iter_init (&hash_iter, priv->hash_scope_to_authentication_agent);
  while (g_hash_table_iter_next (&hash_iter, NULL, (gpointer) &agent))
    {
      GList *l;

      for (l = agent->active_sessions; l != NULL; l = l->next)
        {
          AuthenticationSession *session = l->data;

          if (POLKIT_IS_SYSTEM_BUS_NAME (session->subject) &&
              strcmp (polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (session->subject)),
                      system_bus_unique_name) == 0)
            {
              result = g_list_prepend (result, session);
            }
        }
    }

   return result;
}


static AuthenticationAgent *
get_authentication_agent_by_unique_system_bus_name (PolkitBackendInteractiveAuthority *authority,
                                                    const gchar *unique_system_bus_name)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GHashTableIter hash_iter;
  AuthenticationAgent *agent;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  g_hash_table_iter_init (&hash_iter, priv->hash_scope_to_authentication_agent);
  while (g_hash_table_iter_next (&hash_iter, NULL, (gpointer) &agent))
    {
      if (strcmp (agent->unique_system_bus_name, unique_system_bus_name) == 0)
        goto out;
    }

  agent = NULL;

  out:
  return agent;
}

static void
authentication_agent_begin_cb (GDBusProxy   *proxy,
                               GAsyncResult *res,
                               gpointer      user_data)
{
  AuthenticationSession *session = user_data;
  gboolean gained_authorization;
  gboolean was_dismissed;
  GVariant *result;
  GError *error;

  was_dismissed = FALSE;
  gained_authorization = FALSE;

  error = NULL;
  result = g_dbus_proxy_call_finish (proxy, res, &error);
  if (result == NULL)
    {
      g_printerr ("Error performing authentication: %s (%s %d)\n",
                  error->message,
                  g_quark_to_string (error->domain),
                  error->code);
      if (error->domain == POLKIT_ERROR && error->code == POLKIT_ERROR_CANCELLED)
        was_dismissed = TRUE;
      g_error_free (error);
    }
  else
    {
      g_variant_unref (result);
      gained_authorization = session->is_authenticated;
      g_debug ("Authentication complete, is_authenticated = %d", session->is_authenticated);
    }

  session->agent->active_sessions = g_list_remove (session->agent->active_sessions, session);

  session->callback (session->agent,
                     session->subject,
                     session->user_of_subject,
                     session->caller,
                     session->authority,
                     session->action_id,
                     session->details,
                     session->implicit_authorization,
                     gained_authorization,
                     was_dismissed,
                     session->authenticated_identity,
                     session->user_data);

  authentication_session_free (session);
}

static void
append_property (GString *dest,
                 PolkitDetails *details,
                 const gchar *key,
                 PolkitBackendInteractiveAuthority *authority,
                 const gchar *message,
                 const gchar *action_id)
{
  const gchar *value;

  value = polkit_details_lookup (details, key);
  if (value != NULL)
    {
      g_string_append (dest, value);
    }
  else
    {
      polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                    "Error substituting value for property $(%s) when preparing message `%s' for action-id %s",
                                    key,
                                    message,
                                    action_id);
      g_string_append (dest, "$(");
      g_string_append (dest, key);
      g_string_append (dest, ")");
    }
}

static gchar *
expand_properties (const gchar *message,
                   PolkitDetails *details,
                   PolkitBackendInteractiveAuthority *authority,
                   const gchar *action_id)
{
  GString *ret;
  GString *var;
  guint n;
  gboolean in_resolve;

  ret = g_string_new (NULL);
  var = g_string_new (NULL);

  in_resolve = FALSE;
  for (n = 0; message[n] != '\0'; n++)
    {
      gint c = message[n];
      if (c == '$' && message[n+1] == '(')
        {
          in_resolve = TRUE;
          n += 1;
        }
      else
        {
          if (in_resolve)
            {
              if (c == ')')
                {
                  append_property (ret, details, var->str, authority, message, action_id);
                  g_string_set_size (var, 0);
                  in_resolve = FALSE;
                }
              else
                {
                  g_string_append_c (var, c);
                }
            }
          else
            {
              g_string_append_c (ret, c);
            }
        }
    }
  g_string_free (var, TRUE);

  return g_string_free (ret, FALSE);
}

static void
get_localized_data_for_challenge (PolkitBackendInteractiveAuthority *authority,
                                  PolkitSubject               *caller,
                                  PolkitSubject               *subject,
                                  PolkitIdentity              *user_of_subject,
                                  const gchar                 *action_id,
                                  PolkitDetails               *details,
                                  const gchar                 *locale,
                                  gchar                      **out_localized_message,
                                  gchar                      **out_localized_icon_name,
                                  PolkitDetails              **out_localized_details)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitActionDescription *action_desc;
  gchar *message;
  gchar *icon_name;
  PolkitDetails *localized_details;
  const gchar *message_to_use;
  const gchar *gettext_domain;
  gchar *s;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  message = NULL;
  icon_name = NULL;
  localized_details = NULL;
  action_desc = NULL;

  *out_localized_message = NULL;
  *out_localized_icon_name = NULL;
  *out_localized_details = NULL;

  action_desc = polkit_backend_action_pool_get_action (priv->action_pool,
                                                       action_id,
                                                       locale);
  if (action_desc == NULL)
    goto out;

  /* Set LANG and locale so g_dgettext() + friends work below */
  if (setlocale (LC_ALL, locale) == NULL)
    {
      g_printerr ("Invalid locale '%s'\n", locale);
    }
  /* if LANGUAGE have been set in /etc/default, set LANG is invalid. */
  g_setenv ("LANGUAGE", locale, TRUE);

  gettext_domain = polkit_details_lookup (details, "polkit.gettext_domain");
  message_to_use = polkit_details_lookup (details, "polkit.message");
  if (message_to_use != NULL)
    {
      message = g_strdup (g_dgettext (gettext_domain, message_to_use));
      /* g_print ("locale=%s, domain=%s, msg=`%s' -> `%s'\n", locale, gettext_domain, message_to_use, message); */
    }
  icon_name = g_strdup (polkit_details_lookup (details, "polkit.icon_name"));

  /* fall back to action description */
  if (message == NULL)
    {
      message = g_strdup (polkit_action_description_get_message (action_desc));
    }
  if (icon_name == NULL)
    {
      icon_name = g_strdup (polkit_action_description_get_icon_name (action_desc));
    }

  /* replace $(property) with values */
  if (message != NULL)
    {
      s = message;
      message = expand_properties (message, details, authority, action_id);
      g_free (s);
    }

  /* Back to C! */
  setlocale (LC_ALL, "C");
  g_setenv ("LANGUAGE", "C", TRUE);

 out:
  if (message == NULL)
    message = g_strdup ("");
  if (icon_name == NULL)
    icon_name = g_strdup ("");
  *out_localized_message = message;
  *out_localized_icon_name = icon_name;
  *out_localized_details = localized_details;
  if (action_desc != NULL)
    g_object_unref (action_desc);
}

static void
add_pid (PolkitDetails *details,
         PolkitSubject *subject,
         const gchar   *key)
{
  gchar buf[32];
  gint pid;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject));
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      PolkitSubject *process;
      GError *error;

      error = NULL;
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                         NULL,
                                                         &error);
      if (process == NULL)
        {
          g_printerr ("Error getting process for system bus name `%s': %s\n",
                      polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                      error->message);
          g_error_free (error);
          goto out;
        }
      pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));
      g_object_unref (process);
    }
  else if (POLKIT_IS_UNIX_SESSION (subject))
    {
      goto out;
    }
  else
    {
      gchar *s;
      s = polkit_subject_to_string (subject);
      g_printerr ("Don't know how to get pid from subject of type %s: %s\n",
                  g_type_name (G_TYPE_FROM_INSTANCE (subject)),
                  s);
      g_free (s);
      goto out;
    }

  g_snprintf (buf, sizeof (buf), "%d", pid);
  polkit_details_insert (details, key, buf);

 out:
  ;
}

/* ---------------------------------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------------------------------- */

static GList *
get_users_in_group (PolkitIdentity                    *group,
                    PolkitIdentity                    *user_of_subject,
                    gboolean                           include_root)
{
  gid_t gid;
  uid_t uid_of_subject;
  struct group *grp;
  GList *ret;
  guint n;

  ret = NULL;

  gid = polkit_unix_group_get_gid (POLKIT_UNIX_GROUP (group));

  /* Check if group is subject's primary group. */
  uid_of_subject = polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_of_subject));
  if (uid_of_subject != 0 || include_root)
    {
      struct passwd *pwd;

      pwd = getpwuid (uid_of_subject);
      if (pwd != NULL && pwd->pw_gid == gid)
        ret = g_list_prepend (ret, g_object_ref (user_of_subject));
    }

  /* Add supplemental group members. */
  grp = getgrgid (gid);
  if (grp == NULL)
    {
      g_warning ("Error looking up group with gid %d: %s", gid, g_strerror (errno));
      goto out;
    }

  for (n = 0; grp->gr_mem != NULL && grp->gr_mem[n] != NULL; n++)
    {
      PolkitIdentity *user;
      GError *error;

      if (!include_root && g_strcmp0 (grp->gr_mem[n], "root") == 0)
        continue;

      error = NULL;
      user = polkit_unix_user_new_for_name (grp->gr_mem[n], &error);
      if (user == NULL)
        {
          g_warning ("Unknown username '%s' in group: %s", grp->gr_mem[n], error->message);
          g_error_free (error);
        }
      else
        {
          ret = g_list_prepend (ret, user);
        }
    }

  ret = g_list_reverse (ret);

 out:
  return ret;
}

static GList *
get_users_in_net_group (PolkitIdentity                    *group,
                        gboolean                           include_root)
{
  const gchar *name;
  GList *ret;

  ret = NULL;
#ifdef HAVE_SETNETGRENT
  name = polkit_unix_netgroup_get_name (POLKIT_UNIX_NETGROUP (group));

# ifdef HAVE_SETNETGRENT_RETURN
  if (setnetgrent (name) == 0)
    {
      g_warning ("Error looking up net group with name %s: %s", name, g_strerror (errno));
      goto out;
    }
# else
  setnetgrent (name);
# endif /* HAVE_SETNETGRENT_RETURN */

  for (;;)
    {
# if defined(HAVE_NETBSD) || defined(HAVE_OPENBSD)
      const char *hostname, *username, *domainname;
# else
      char *hostname, *username, *domainname;
# endif /* defined(HAVE_NETBSD) || defined(HAVE_OPENBSD) */
      PolkitIdentity *user;
      GError *error = NULL;

      if (getnetgrent (&hostname, &username, &domainname) == 0)
        break;

      /* Skip NULL entries since we never want to make everyone an admin
       * Skip "-" entries which mean "no match ever" in netgroup land */
      if (username == NULL || g_strcmp0 (username, "-") == 0)
        continue;

      /* TODO: Should we match on hostname? Maybe only allow "-" as a hostname
       * for safety. */

      user = polkit_unix_user_new_for_name (username, &error);
      if (user == NULL)
        {
          g_warning ("Unknown username '%s' in unix-netgroup: %s", username, error->message);
          g_error_free (error);
        }
      else
        {
          ret = g_list_prepend (ret, user);
        }
    }

  ret = g_list_reverse (ret);

 out:
  endnetgrent ();
#endif /* HAVE_SETNETGRENT */
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authentication_agent_initiate_challenge (AuthenticationAgent         *agent,
                                         PolkitSubject               *subject,
                                         PolkitIdentity              *user_of_subject,
                                         PolkitBackendInteractiveAuthority *authority,
                                         const gchar                 *action_id,
                                         PolkitDetails               *details,
                                         PolkitSubject               *caller,
                                         PolkitImplicitAuthorization  implicit_authorization,
                                         GCancellable                *cancellable,
                                         AuthenticationAgentCallback  callback,
                                         gpointer                     user_data)
{
  PolkitBackendInteractiveAuthorityPrivate *priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);
  AuthenticationSession *session;
  GList *l;
  GList *identities;
  gchar *localized_message;
  gchar *localized_icon_name;
  PolkitDetails *localized_details;
  GList *user_identities = NULL;
  GVariantBuilder identities_builder;
  GVariant *parameters;

  get_localized_data_for_challenge (authority,
                                    caller,
                                    subject,
                                    user_of_subject,
                                    action_id,
                                    details,
                                    agent->locale,
                                    &localized_message,
                                    &localized_icon_name,
                                    &localized_details);

  identities = NULL;

  /* select admin user if required by the implicit authorization */
  if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED ||
      implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
    {
      gboolean is_local = FALSE;
      gboolean is_active = FALSE;
      PolkitSubject *session_for_subject = NULL;

      session_for_subject = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                                    subject,
                                                                                    NULL);
      if (session_for_subject != NULL)
        {
          is_local = polkit_backend_session_monitor_is_session_local (priv->session_monitor, session_for_subject);
          is_active = polkit_backend_session_monitor_is_session_active (priv->session_monitor, session_for_subject);
        }

      identities = polkit_backend_interactive_authority_get_admin_identities (authority,
                                                                              caller,
                                                                              subject,
                                                                              user_of_subject,
                                                                              is_local,
                                                                              is_active,
                                                                              action_id,
                                                                              details);
      g_clear_object (&session_for_subject);
    }
  else
    {
      identities = g_list_prepend (identities, g_object_ref (user_of_subject));
    }

  /* expand groups/netgroups to users */
  user_identities = NULL;
  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      if (POLKIT_IS_UNIX_USER (identity))
        {
          user_identities = g_list_append (user_identities, g_object_ref (identity));
        }
      else if (POLKIT_IS_UNIX_GROUP (identity))
        {
          user_identities = g_list_concat (user_identities, get_users_in_group (identity, user_of_subject, FALSE));
        }
      else if (POLKIT_IS_UNIX_NETGROUP (identity))
        {
          user_identities =  g_list_concat (user_identities, get_users_in_net_group (identity, FALSE));
        }
      else
        {
          g_warning ("Unsupported identity");
        }
    }

  /* Fall back to uid 0 if no users are available (rhbz #834494) */
  if (user_identities == NULL)
    user_identities = g_list_prepend (NULL, polkit_unix_user_new (0));

  session = authentication_session_new (agent,
                                        subject,
                                        user_of_subject,
                                        caller,
                                        authority,
                                        user_identities,
                                        action_id,
                                        details,
                                        polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                        implicit_authorization,
                                        cancellable,
                                        callback,
                                        user_data);

  agent->active_sessions = g_list_prepend (agent->active_sessions, session);

  if (localized_details == NULL)
    localized_details = polkit_details_new ();
  add_pid (localized_details, caller, "polkit.caller-pid");
  add_pid (localized_details, subject, "polkit.subject-pid");

  g_variant_builder_init (&identities_builder, G_VARIANT_TYPE ("a(sa{sv})"));
  for (l = user_identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      g_variant_builder_add_value (&identities_builder,
                                   polkit_identity_to_gvariant (identity)); /* A floating value */
    }

  parameters = g_variant_new ("(sss@a{ss}sa(sa{sv}))",
                              action_id,
                              localized_message,
                              localized_icon_name,
                              polkit_details_to_gvariant (localized_details), /* A floating value */
                              session->cookie,
                              &identities_builder);

  g_dbus_proxy_call (agent->proxy,
                     "BeginAuthentication",
                     parameters, /* consumes the floating GVariant */
                     G_DBUS_CALL_FLAGS_NONE,
                     G_MAXINT, /* timeout_msec - no timeout */
                     session->cancellable,
                     (GAsyncReadyCallback) authentication_agent_begin_cb,
                     session);

  g_list_free_full (user_identities, g_object_unref);
  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);

  g_free (localized_message);
  g_free (localized_icon_name);
  if (localized_details != NULL)
    g_object_unref (localized_details);
}

static void
authentication_agent_cancel_cb (GDBusProxy   *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
  GVariant *result;
  GError *error;

  error = NULL;
  result = g_dbus_proxy_call_finish (proxy, res, &error);
  if (result == NULL)
    {
      g_printerr ("Error cancelling authentication: %s\n", error->message);
      g_error_free (error);
    }
  else
    g_variant_unref (result);
}

static void
authentication_session_cancel (AuthenticationSession *session)
{
  g_dbus_proxy_call (session->agent->proxy,
                     "CancelAuthentication",
                     g_variant_new ("(s)", session->cookie),
                     G_DBUS_CALL_FLAGS_NONE,
                     -1, /* timeout_msec */
                     NULL, /* GCancellable* */
                     (GAsyncReadyCallback) authentication_agent_cancel_cb,
                     NULL);
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_backend_interactive_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                                    PolkitSubject            *caller,
                                                                    PolkitSubject            *subject,
                                                                    const gchar              *locale,
                                                                    const gchar              *object_path,
                                                                    GVariant                 *options,
                                                                    GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_caller;
  PolkitIdentity *user_of_caller;
  PolkitIdentity *user_of_subject;
  gboolean user_of_subject_matches;
  AuthenticationAgent *agent;
  gboolean ret;
  gchar *caller_cmdline;
  gchar *subject_as_string;

  ret = FALSE;

  session_for_caller = NULL;
  user_of_caller = NULL;
  user_of_subject = NULL;
  subject_as_string = NULL;
  caller_cmdline = NULL;
  agent = NULL;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  if (POLKIT_IS_UNIX_SESSION (subject))
    {
      session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                                   caller,
                                                                                   NULL);
      if (session_for_caller == NULL)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot determine session the caller is in");
          goto out;
        }
      if (!polkit_subject_equal (session_for_caller, subject))
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Passed session and the session the caller is in differs. They must be equal for now.");
          goto out;
        }
    }
  else if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      /* explicitly OK */
    }
  else
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Only unix-process and unix-session subjects can be used for authentication agents.");
      goto out;
    }

  user_of_caller = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor, caller, NULL, NULL);
  if (user_of_caller == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine user of caller");
      goto out;
    }
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor, subject, &user_of_subject_matches, NULL);
  if (user_of_subject == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine user of subject");
      goto out;
    }
  if (!user_of_subject_matches
      || !polkit_identity_equal (user_of_caller, user_of_subject))
    {
      if (identity_is_root_user (user_of_caller))
        {
          /* explicitly allow uid 0 to register for other users */
        }
      else
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "User of caller and user of subject differs.");
          goto out;
        }
    }

  agent = g_hash_table_lookup (priv->hash_scope_to_authentication_agent, subject);
  if (agent != NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "An authentication agent already exists for the given subject");
      goto out;
    }

  priv->agent_serial++;
  agent = authentication_agent_new (priv->agent_serial,
                                    subject,
                                    user_of_caller,
                                    polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                    locale,
                                    object_path,
                                    options,
                                    error);
  if (!agent)
    goto out;

  g_hash_table_insert (priv->hash_scope_to_authentication_agent,
                       g_object_ref (subject),
                       agent);

  caller_cmdline = _polkit_subject_get_cmdline (caller);
  if (caller_cmdline == NULL)
    caller_cmdline = g_strdup ("<unknown>");

  subject_as_string = polkit_subject_to_string (subject);

  g_debug ("Added authentication agent for %s at name %s [%s], object path %s, locale %s",
           subject_as_string,
           polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
           caller_cmdline,
           object_path,
           locale);

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Registered Authentication Agent for %s "
                                "(system bus name %s [%s], object path %s, locale %s)",
                                subject_as_string,
                                polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                caller_cmdline,
                                object_path,
                                locale);

  g_signal_emit_by_name (authority, "changed");

  ret = TRUE;

 out:
  g_free (caller_cmdline);
  g_free (subject_as_string);
  if (user_of_caller != NULL)
    g_object_unref (user_of_caller);
  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);

  return ret;
}

static gboolean
polkit_backend_interactive_authority_unregister_authentication_agent (PolkitBackendAuthority   *authority,
                                                                      PolkitSubject            *caller,
                                                                      PolkitSubject            *subject,
                                                                      const gchar              *object_path,
                                                                      GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_caller;
  PolkitIdentity *user_of_caller;
  PolkitIdentity *user_of_subject;
  gboolean user_of_subject_matches;
  AuthenticationAgent *agent;
  gboolean ret;
  gchar *scope_str;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  ret = FALSE;
  session_for_caller = NULL;
  user_of_caller = NULL;
  user_of_subject = NULL;

  if (POLKIT_IS_UNIX_SESSION (subject))
    {
      session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                                   caller,
                                                                                   NULL);
      if (session_for_caller == NULL)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot determine session the caller is in");
          goto out;
        }

      if (!polkit_subject_equal (session_for_caller, subject))
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Passed session and the session the caller is in differs. They must be equal for now.");
          goto out;
        }
    }
  else if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      /* explicitly OK */
    }
  else
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Only unix-process and unix-session subjects can be used for authentication agents.");
      goto out;
    }

  user_of_caller = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor, caller, NULL, NULL);
  if (user_of_caller == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine user of caller");
      goto out;
    }
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor, subject, &user_of_subject_matches, NULL);
  if (user_of_subject == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine user of subject");
      goto out;
    }
  if (!user_of_subject_matches
      || !polkit_identity_equal (user_of_caller, user_of_subject))
    {
      if (identity_is_root_user (user_of_caller))
        {
          /* explicitly allow uid 0 to register for other users */
        }
      else
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "User of caller and user of subject differs.");
          goto out;
        }
    }

  agent = g_hash_table_lookup (priv->hash_scope_to_authentication_agent, subject);
  if (agent == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "No such agent registered");
      goto out;
    }

  if (g_strcmp0 (agent->unique_system_bus_name, polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller))) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "System bus names do not match");
      goto out;
    }

  if (g_strcmp0 (agent->object_path, object_path) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Object paths do not match");
      goto out;
    }

  scope_str = polkit_subject_to_string (agent->scope);
  g_debug ("Removing authentication agent for %s at name %s, object path %s, locale %s",
           scope_str,
           agent->unique_system_bus_name,
           agent->object_path,
           agent->locale);

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Unregistered Authentication Agent for %s "
                                "(system bus name %s, object path %s, locale %s)",
                                scope_str,
                                agent->unique_system_bus_name,
                                agent->object_path,
                                agent->locale);
  g_free (scope_str);

  authentication_agent_cancel_all_sessions (agent);
  /* this works because we have exactly one agent per session */
  /* this frees agent... */
  g_hash_table_remove (priv->hash_scope_to_authentication_agent, agent->scope);

  g_signal_emit_by_name (authority, "changed");

  ret = TRUE;

 out:
  if (user_of_caller != NULL)
    g_object_unref (user_of_caller);
  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_backend_interactive_authority_authentication_agent_response (PolkitBackendAuthority   *authority,
                                                              PolkitSubject            *caller,
                                                              uid_t                     uid,
                                                              const gchar              *cookie,
                                                              PolkitIdentity           *identity,
                                                              GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitIdentity *user_of_caller;
  gchar *identity_str;
  AuthenticationSession *session;
  GList *l;
  gboolean ret;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  ret = FALSE;
  user_of_caller = NULL;

  identity_str = polkit_identity_to_string (identity);

  g_debug ("In authentication_agent_response for cookie '%s' and identity %s",
           cookie,
           identity_str);

  user_of_caller = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                        caller, NULL,
                                                                        error);
  if (user_of_caller == NULL)
    goto out;

  /* only uid 0 is allowed to invoke this method */
  if (!identity_is_root_user (user_of_caller))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Only uid 0 may invoke this method. This incident has been logged.");
      /* TODO: actually log this */
      goto out;
    }

  /* find the authentication session */
  session = get_authentication_session_for_uid_and_cookie (interactive_authority, uid, cookie);
  if (session == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "No session for cookie");
      goto out;
    }

  /* check that the authentication identity was one of the possibilities we allowed */
  for (l = session->identities; l != NULL; l = l->next)
    {
      PolkitIdentity *i = POLKIT_IDENTITY (l->data);

      if (polkit_identity_equal (i, identity))
        break;
    }

  if (l == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "The authenticated identity is wrong");
      goto out;
    }

  /* checks out, mark the session as authenticated */
  session->is_authenticated = TRUE;
  session->authenticated_identity = g_object_ref (identity);

  ret = TRUE;

 out:
  g_free (identity_str);

  if (user_of_caller != NULL)
    g_object_unref (user_of_caller);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_interactive_authority_system_bus_name_owner_changed (PolkitBackendInteractiveAuthority *authority,
                                                                    const gchar                       *name,
                                                                    const gchar                       *old_owner,
                                                                    const gchar                       *new_owner)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  //g_debug ("name-owner-changed: '%s' '%s' '%s'", name, old_owner, new_owner);

  if (name[0] == ':' && strlen (new_owner) == 0)
    {
      AuthenticationAgent *agent;
      GList *sessions;
      GList *l;

      agent = get_authentication_agent_by_unique_system_bus_name (interactive_authority, name);
      if (agent != NULL)
        {
          gchar *scope_str;

          scope_str = polkit_subject_to_string (agent->scope);
          g_debug ("Removing authentication agent for %s at name %s, object path %s (disconnected from bus)",
                   scope_str,
                   agent->unique_system_bus_name,
                   agent->object_path);

          polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                        "Unregistered Authentication Agent for %s "
                                        "(system bus name %s, object path %s, locale %s) (disconnected from bus)",
                                        scope_str,
                                        agent->unique_system_bus_name,
                                        agent->object_path,
                                        agent->locale);
          g_free (scope_str);

          authentication_agent_cancel_all_sessions (agent);
          /* this works because we have exactly one agent per session */
          /* this frees agent... */
          g_hash_table_remove (priv->hash_scope_to_authentication_agent, agent->scope);

          g_signal_emit_by_name (authority, "changed");
        }

      /* cancel all authentication sessions initiated by the process owning the vanished name */
      sessions = get_authentication_sessions_initiated_by_system_bus_unique_name (interactive_authority, name);
      for (l = sessions; l != NULL; l = l->next)
        {
          AuthenticationSession *session = l->data;

          authentication_session_cancel (session);
        }
      g_list_free (sessions);

      /* cancel all authentication sessions that is about the vanished name */
      sessions = get_authentication_sessions_for_system_bus_unique_name_subject (interactive_authority, name);
      for (l = sessions; l != NULL; l = l->next)
        {
          AuthenticationSession *session = l->data;

          authentication_session_cancel (session);
        }
      g_list_free (sessions);

      /* remove all temporary authorizations that applies to the vanished name
       * (temporary_authorization_store_add_authorization for the code path for handling processes)
       */
      temporary_authorization_store_remove_authorizations_for_system_bus_name (priv->temporary_authorization_store,
                                                                               name);

    }

}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct TemporaryAuthorization TemporaryAuthorization;

struct TemporaryAuthorizationStore
{
  GList *authorizations;
  PolkitBackendInteractiveAuthority *authority;
  guint64 serial;
};

struct TemporaryAuthorization
{
  TemporaryAuthorizationStore *store;
  PolkitSubject *subject;
  PolkitSubject *scope;
  gchar *id;
  gchar *action_id;
  /* both of these are obtained using g_get_monotonic_time(),
   * so the resolution is usec
   */
  gint64 time_granted;
  gint64 time_expires;
  guint expiration_timeout_id;
  guint check_vanished_timeout_id;
};

static void
temporary_authorization_free (TemporaryAuthorization *authorization)
{
  g_free (authorization->id);
  g_object_unref (authorization->subject);
  g_object_unref (authorization->scope);
  g_free (authorization->action_id);
  if (authorization->expiration_timeout_id > 0)
    g_source_remove (authorization->expiration_timeout_id);
  if (authorization->check_vanished_timeout_id > 0)
    g_source_remove (authorization->check_vanished_timeout_id);
  g_free (authorization);
}

static TemporaryAuthorizationStore *
temporary_authorization_store_new (PolkitBackendInteractiveAuthority *authority)
{
  TemporaryAuthorizationStore *store;

  store = g_new0 (TemporaryAuthorizationStore, 1);
  store->authority = authority;
  store->authorizations = NULL;

  return store;
}

static void
temporary_authorization_store_free (TemporaryAuthorizationStore *store)
{
  g_list_foreach (store->authorizations, (GFunc) temporary_authorization_free, NULL);
  g_list_free (store->authorizations);
  g_free (store);
}

/* XXX: for now, prefer to store the process; see
 * https://bugs.freedesktop.org/show_bug.cgi?id=23867
 */
static PolkitSubject *
convert_temporary_authorization_subject (PolkitSubject *subject)
{
  PolkitSubject *ret;
  if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      GError *error = NULL;
      ret = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                     NULL,
                                                     &error);
      if (ret == NULL)
        {
          g_printerr ("Error getting process for system bus name `%s': %s\n",
                      polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                      error->message);
          g_error_free (error);
          return g_object_ref (subject);
        }
      else
        {
          return ret;
        }
    }
  else
    {
      return g_object_ref (subject);
    }
}

/* See the comment at the top of polkitunixprocess.c */
static gboolean
subject_equal_for_authz (PolkitSubject *a,
                         PolkitSubject *b)
{
  if (!polkit_subject_equal (a, b))
    return FALSE;

  /* Now special case unix processes, as we want to protect against
   * pid reuse by including the UID.
   */
  if (POLKIT_IS_UNIX_PROCESS (a) && POLKIT_IS_UNIX_PROCESS (b)) {
    int uid_a = polkit_unix_process_get_uid ((PolkitUnixProcess*)a);
    int uid_b = polkit_unix_process_get_uid ((PolkitUnixProcess*)b);

    if (uid_a != -1 && uid_b != -1)
      {
        if (uid_a == uid_b)
          {
            return TRUE;
          }
        else
          {
            g_printerr ("denying slowfork; pid %d uid %d != %d!\n",
                        polkit_unix_process_get_pid ((PolkitUnixProcess*)a),
                        uid_a, uid_b);
            return FALSE;
          }
      }
    /* Fall through; one of the uids is unset so we can't reliably compare */
  }

  return TRUE;
}

static gboolean
temporary_authorization_store_has_authorization (TemporaryAuthorizationStore *store,
                                                 PolkitSubject               *subject,
                                                 const gchar                 *action_id,
                                                 const gchar                **out_tmp_authz_id)
{
  GList *l;
  gboolean ret;
  PolkitSubject *subject_to_use;

  g_return_val_if_fail (store != NULL, FALSE);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), FALSE);
  g_return_val_if_fail (action_id != NULL, FALSE);

  subject_to_use = convert_temporary_authorization_subject (subject);

  ret = FALSE;

  for (l = store->authorizations; l != NULL; l = l->next) {
    TemporaryAuthorization *authorization = l->data;

    if (strcmp (action_id, authorization->action_id) == 0 &&
        subject_equal_for_authz (subject_to_use, authorization->subject))
      {
        ret = TRUE;
        if (out_tmp_authz_id != NULL)
          *out_tmp_authz_id = authorization->id;
        goto out;
      }
  }

 out:
  g_object_unref (subject_to_use);
  return ret;
}

static gboolean
on_expiration_timeout (gpointer user_data)
{
  TemporaryAuthorization *authorization = user_data;
  gchar *s;

  s = polkit_subject_to_string (authorization->subject);
  g_debug ("Removing tempoary authorization with id `%s' for action-id `%s' for subject `%s': "
           "authorization has expired",
           authorization->id,
           authorization->action_id,
           s);
  g_free (s);

  authorization->store->authorizations = g_list_remove (authorization->store->authorizations,
                                                        authorization);
  authorization->expiration_timeout_id = 0;
  g_signal_emit_by_name (authorization->store->authority, "changed");
  temporary_authorization_free (authorization);

  /* remove source */
  return FALSE;
}

static gboolean
on_unix_process_check_vanished_timeout (gpointer user_data)
{
  TemporaryAuthorization *authorization = user_data;
  GError *error;

  /* we know that this is a PolkitUnixProcess so the check is fast (no IPC involved) */
  error = NULL;
  if (!polkit_subject_exists_sync (authorization->subject,
                                   NULL,
                                   &error))
    {
      if (error != NULL)
        {
          g_printerr ("Error checking if process exists: %s\n", error->message);
          g_error_free (error);
        }
      else
        {
          gchar *s;

          s = polkit_subject_to_string (authorization->subject);
          g_debug ("Removing tempoary authorization with id `%s' for action-id `%s' for subject `%s': "
                   "subject has vanished",
                   authorization->id,
                   authorization->action_id,
                   s);
          g_free (s);

          authorization->store->authorizations = g_list_remove (authorization->store->authorizations,
                                                                authorization);
          g_signal_emit_by_name (authorization->store->authority, "changed");
          temporary_authorization_free (authorization);
        }
    }

  /* keep source around */
  return TRUE;
}

static void
temporary_authorization_store_remove_authorizations_for_system_bus_name (TemporaryAuthorizationStore *store,
                                                                         const gchar *name)
{
  guint num_removed;
  GList *l, *ll;

  num_removed = 0;
  for (l = store->authorizations; l != NULL; l = ll)
    {
      TemporaryAuthorization *ta = l->data;
      gchar *s;

      ll = l->next;

      if (!POLKIT_IS_SYSTEM_BUS_NAME (ta->subject))
        continue;

      if (g_strcmp0 (name, polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (ta->subject))) != 0)
        continue;


      s = polkit_subject_to_string (ta->subject);
      g_debug ("Removing tempoary authorization with id `%s' for action-id `%s' for subject `%s': "
               "subject has vanished",
               ta->id,
               ta->action_id,
               s);
      g_free (s);

      store->authorizations = g_list_remove (store->authorizations, ta);
      temporary_authorization_free (ta);

      num_removed++;
    }

  if (num_removed > 0)
    g_signal_emit_by_name (store->authority, "changed");
}

static const gchar *
temporary_authorization_store_add_authorization (TemporaryAuthorizationStore *store,
                                                 PolkitSubject               *subject,
                                                 PolkitSubject               *scope,
                                                 const gchar                 *action_id)
{
  TemporaryAuthorization *authorization;
  guint expiration_seconds;
  PolkitSubject *subject_to_use;

  g_return_val_if_fail (store != NULL, NULL);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), NULL);
  g_return_val_if_fail (action_id != NULL, NULL);
  g_return_val_if_fail (!temporary_authorization_store_has_authorization (store, subject, action_id, NULL), NULL);

  subject_to_use = convert_temporary_authorization_subject (subject);

  /* TODO: right now the time the temporary authorization is kept is hard-coded - we
   *       could make it a propery on the PolkitBackendInteractiveAuthority class (so
   *       the local authority could read it from a config file) or a vfunc
   *       (so the local authority could read it from an annotation on the action).
   */
  expiration_seconds = 5 * 60;

  authorization = g_new0 (TemporaryAuthorization, 1);
  authorization->id = g_strdup_printf ("tmpauthz%" G_GUINT64_FORMAT, store->serial++);
  authorization->store = store;
  authorization->subject = g_object_ref (subject_to_use);
  authorization->scope = g_object_ref (scope);
  authorization->action_id = g_strdup (action_id);
  /* store monotonic time and convert to secs-since-epoch when returning TemporaryAuthorization structs */
  authorization->time_granted = g_get_monotonic_time ();
  authorization->time_expires = authorization->time_granted + expiration_seconds * G_USEC_PER_SEC;
  /* g_timeout_add() is using monotonic time since 2.28 */
  authorization->expiration_timeout_id = g_timeout_add (expiration_seconds * 1000,
                                                        on_expiration_timeout,
                                                        authorization);

  if (POLKIT_IS_UNIX_PROCESS (authorization->subject))
    {
      /* For now, set up a timer to poll every two seconds - this is used to determine
       * when the process vanishes. We want to do this so we can remove the temporary
       * authorization - this is because we want agents to update e.g. a notification
       * area icon saying the user has temporary authorizations (e.g. remove the icon).
       *
       * Ideally we'd just do
       *
       *   g_signal_connect (kernel, "process-exited", G_CALLBACK (on_process_exited), user_data);
       *
       * but that is not how things work right now (and, hey, it's not like the kernel
       * is a GObject either!) - so we poll.
       *
       * TODO: On Linux, it might be possible to obtain notifications by connecting
       *       to the netlink socket. Needs looking into.
       */

      authorization->check_vanished_timeout_id = g_timeout_add_seconds (2,
                                                                        on_unix_process_check_vanished_timeout,
                                                                        authorization);
    }
#if 0
  else if (POLKIT_IS_SYSTEM_BUS_NAME (authorization->subject))
    {
      /* This is currently handled in polkit_backend_interactive_authority_system_bus_name_owner_changed()  */
    }
#endif


  store->authorizations = g_list_prepend (store->authorizations, authorization);

  g_object_unref (subject_to_use);

  return authorization->id;
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
polkit_backend_interactive_authority_enumerate_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                                         PolkitSubject            *caller,
                                                                         PolkitSubject            *subject,
                                                                         GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_caller;
  GList *ret;
  GList *l;
  gint64 monotonic_now;
  GTimeVal real_now;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  ret = NULL;
  session_for_caller = NULL;

  if (!POLKIT_IS_UNIX_SESSION (subject))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Can only handle PolkitUnixSession objects for now.");
      goto out;
    }

  session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                               caller,
                                                                               NULL);
  if (session_for_caller == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine session the caller is in");
      goto out;
    }

  if (!polkit_subject_equal (session_for_caller, subject))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Passed session and the session the caller is in differs. They must be equal for now.");
      goto out;
    }

  monotonic_now = g_get_monotonic_time ();
  g_get_current_time (&real_now);

  for (l = priv->temporary_authorization_store->authorizations; l != NULL; l = l->next)
    {
      TemporaryAuthorization *ta = l->data;
      PolkitTemporaryAuthorization *tmp_authz;
      guint64 real_granted;
      guint64 real_expires;

      if (!polkit_subject_equal (ta->scope, subject))
        continue;

      real_granted = (ta->time_granted - monotonic_now) / G_USEC_PER_SEC + real_now.tv_sec;
      real_expires = (ta->time_expires - monotonic_now) / G_USEC_PER_SEC + real_now.tv_sec;

      tmp_authz = polkit_temporary_authorization_new (ta->id,
                                                      ta->action_id,
                                                      ta->subject,
                                                      real_granted,
                                                      real_expires);

      ret = g_list_prepend (ret, tmp_authz);
    }

 out:
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_backend_interactive_authority_revoke_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                                      PolkitSubject            *caller,
                                                                      PolkitSubject            *subject,
                                                                      GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_caller;
  gboolean ret;
  GList *l;
  GList *ll;
  guint num_removed;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  ret = FALSE;
  session_for_caller = NULL;

  if (!POLKIT_IS_UNIX_SESSION (subject))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Can only handle PolkitUnixSession objects for now.");
      goto out;
    }

  session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                               caller,
                                                                               NULL);
  if (session_for_caller == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine session the caller is in");
      goto out;
    }

  if (!polkit_subject_equal (session_for_caller, subject))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Passed session and the session the caller is in differs. They must be equal for now.");
      goto out;
    }

  num_removed = 0;
  for (l = priv->temporary_authorization_store->authorizations; l != NULL; l = ll)
    {
      TemporaryAuthorization *ta = l->data;

      ll = l->next;

      if (!polkit_subject_equal (ta->scope, subject))
        continue;

      priv->temporary_authorization_store->authorizations = g_list_remove (priv->temporary_authorization_store->authorizations, ta);
      temporary_authorization_free (ta);

      num_removed++;
    }

  if (num_removed > 0)
    g_signal_emit_by_name (authority, "changed");

  ret = TRUE;

 out:
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_backend_interactive_authority_revoke_temporary_authorization_by_id (PolkitBackendAuthority   *authority,
                                                                           PolkitSubject            *caller,
                                                                           const gchar              *id,
                                                                           GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_caller;
  gboolean ret;
  GList *l;
  GList *ll;
  guint num_removed;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  ret = FALSE;
  session_for_caller = NULL;

  session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                               caller,
                                                                               NULL);
  if (session_for_caller == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine session the caller is in");
      goto out;
    }

  num_removed = 0;
  for (l = priv->temporary_authorization_store->authorizations; l != NULL; l = ll)
    {
      TemporaryAuthorization *ta = l->data;

      ll = l->next;

      if (strcmp (ta->id, id) != 0)
        continue;

      if (!polkit_subject_equal (session_for_caller, ta->scope))
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot remove a temporary authorization belonging to another subject.");
          goto out;
        }

      priv->temporary_authorization_store->authorizations = g_list_remove (priv->temporary_authorization_store->authorizations, ta);
      temporary_authorization_free (ta);

      num_removed++;
    }

  if (num_removed > 0)
    {
      g_signal_emit_by_name (authority, "changed");
    }
  else
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "No such authorization with id `%s'",
                   id);
      goto out;
    }

  ret = TRUE;

 out:
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

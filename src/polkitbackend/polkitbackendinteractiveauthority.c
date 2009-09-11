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
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>

#include <polkit/polkit.h>
#include "polkitbackendinteractiveauthority.h"
#include "polkitbackendactionpool.h"
#include "polkitbackendsessionmonitor.h"
#include "polkitbackendconfigsource.h"
#include "polkitbackendactionlookup.h"

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
                                             PolkitBackendInteractiveAuthority *authority,
                                             const gchar                 *action_id,
                                             PolkitImplicitAuthorization  implicit_authorization,
                                             gboolean                     authentication_success,
                                             gpointer                     user_data);

static void                authentication_agent_free (AuthenticationAgent *agent);

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

static PolkitSubject *authentication_agent_get_session (AuthenticationAgent *agent);

static AuthenticationAgent *get_authentication_agent_for_subject (PolkitBackendInteractiveAuthority *authority,
                                                                  PolkitSubject *subject);


static AuthenticationSession *get_authentication_session_for_cookie (PolkitBackendInteractiveAuthority *authority,
                                                                     const gchar *cookie);

static GList *get_authentication_sessions_initiated_by_system_bus_unique_name (PolkitBackendInteractiveAuthority *authority,
                                                                               const gchar *system_bus_unique_name);

static void authentication_session_cancel (AuthenticationSession *session);

/* ---------------------------------------------------------------------------------------------------- */

static void polkit_backend_interactive_authority_system_bus_name_owner_changed (PolkitBackendAuthority   *authority,
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
                                                            GError                        **error);

static gboolean polkit_backend_interactive_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                                                    PolkitSubject            *caller,
                                                                                    PolkitSubject            *subject,
                                                                                    const gchar              *locale,
                                                                                    const gchar              *object_path,
                                                                                    GError                  **error);

static gboolean polkit_backend_interactive_authority_unregister_authentication_agent (PolkitBackendAuthority   *authority,
                                                                                      PolkitSubject            *caller,
                                                                                      PolkitSubject            *subject,
                                                                                      const gchar              *object_path,
                                                                                      GError                  **error);

static gboolean polkit_backend_interactive_authority_authentication_agent_response (PolkitBackendAuthority   *authority,
                                                                              PolkitSubject            *caller,
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

  GHashTable *hash_session_to_authentication_agent;

} PolkitBackendInteractiveAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

G_DEFINE_TYPE (PolkitBackendInteractiveAuthority,
               polkit_backend_interactive_authority,
               POLKIT_BACKEND_TYPE_AUTHORITY);

#define POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY, PolkitBackendInteractiveAuthorityPrivate))

/* ---------------------------------------------------------------------------------------------------- */

static void
action_pool_changed (PolkitBackendActionPool *action_pool,
                     PolkitBackendInteractiveAuthority *authority)
{
  g_signal_emit_by_name (authority, "changed");
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

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  directory = g_file_new_for_path (PACKAGE_DATA_DIR "/polkit-1/actions");
  priv->action_pool = polkit_backend_action_pool_new (directory);
  g_object_unref (directory);
  g_signal_connect (priv->action_pool,
                    "changed",
                    (GCallback) action_pool_changed,
                    authority);

  priv->temporary_authorization_store = temporary_authorization_store_new (authority);

  priv->hash_session_to_authentication_agent = g_hash_table_new_full ((GHashFunc) polkit_subject_hash,
                                                                      (GEqualFunc) polkit_subject_equal,
                                                                      (GDestroyNotify) g_object_unref,
                                                                      (GDestroyNotify) authentication_agent_free);

  priv->session_monitor = polkit_backend_session_monitor_new ();
  g_signal_connect (priv->session_monitor,
                    "changed",
                    G_CALLBACK (on_session_monitor_changed),
                    authority);
}

static void
polkit_backend_interactive_authority_finalize (GObject *object)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (object);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  if (priv->action_pool != NULL)
    g_object_unref (priv->action_pool);

  if (priv->session_monitor != NULL)
    g_object_unref (priv->session_monitor);

  temporary_authorization_store_free (priv->temporary_authorization_store);

  g_hash_table_unref (priv->hash_session_to_authentication_agent);

  G_OBJECT_CLASS (polkit_backend_interactive_authority_parent_class)->finalize (object);
}

static void
polkit_backend_interactive_authority_class_init (PolkitBackendInteractiveAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);

  gobject_class->finalize = polkit_backend_interactive_authority_finalize;

  authority_class->system_bus_name_owner_changed   = polkit_backend_interactive_authority_system_bus_name_owner_changed;
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

static void
check_authorization_challenge_cb (AuthenticationAgent         *agent,
                                  PolkitSubject               *subject,
                                  PolkitIdentity              *user_of_subject,
                                  PolkitBackendInteractiveAuthority *authority,
                                  const gchar                 *action_id,
                                  PolkitImplicitAuthorization  implicit_authorization,
                                  gboolean                     authentication_success,
                                  gpointer                     user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitAuthorizationResult *result;
  gchar *subject_str;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  result = NULL;
  subject_str = polkit_subject_to_string (subject);

  g_debug ("In check_authorization_challenge_cb\n"
           "  subject                %s\n"
           "  action_id              %s\n"
           "  authentication_success %d\n",
           subject_str,
           action_id,
           authentication_success);

  if (authentication_success)
    {
      PolkitDetails *details;

      details = polkit_details_new ();

      /* store temporary authorization depending on value of implicit_authorization */
      if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED ||
          implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
        {
          const gchar *id;

          id = temporary_authorization_store_add_authorization (priv->temporary_authorization_store,
                                                                subject,
                                                                authentication_agent_get_session (agent),
                                                                action_id);

          polkit_details_insert (details, "polkit.temporary_authorization_id", id);

          /* we've added a temporary authorization, let the user know */
          g_signal_emit_by_name (authority, "changed");
        }

      result = polkit_authorization_result_new (TRUE, FALSE, details);
      g_object_unref (details);
    }
  else
    {
      /* TODO: maybe return set is_challenge? */
      result = polkit_authorization_result_new (FALSE, FALSE, NULL);
    }

  g_simple_async_result_set_op_res_gpointer (simple,
                                             result,
                                             g_object_unref);
  g_simple_async_result_complete (simple);
  g_object_unref (simple);

  g_free (subject_str);
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

  caller_str = polkit_subject_to_string (caller);
  subject_str = polkit_subject_to_string (subject);

  g_debug ("%s is inquiring whether %s is authorized for %s",
           caller_str,
           subject_str,
           action_id);

  user_of_caller = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                        caller,
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
                                                                         subject,
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
  if (!polkit_identity_equal (user_of_caller, user_of_subject) || has_details)
    {
      /* we only allow trusted callers (uid 0 + others) to check authorizations for subjects
       * they don't own - and only if there are no details passed (to avoid spoofing dialogs).
       *
       * TODO: allow other uids like 'haldaemon'?
       */
      if (!POLKIT_IS_UNIX_USER (user_of_caller) ||
          polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_of_caller)) != 0)
        {
          g_simple_async_result_set_error (simple,
                                           POLKIT_ERROR,
                                           POLKIT_ERROR_NOT_AUTHORIZED,
                                           "Only trusted callers can use CheckAuthorization() for subjects "
                                           "belonging to other identities and/or pass details");
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

  /* Otherwise just return the result */
  g_simple_async_result_set_op_res_gpointer (simple,
                                             result,
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
  PolkitDetails *result_details;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  result = NULL;

  user_of_subject = NULL;
  groups_of_user = NULL;
  subject_str = NULL;
  session_for_subject = NULL;
  result_details = NULL;

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

  /* every subject has a user */
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject,
                                                                         error);
  if (user_of_subject == NULL)
      goto out;

  /* special case: uid 0, root, is _always_ authorized for anything */
  if (POLKIT_IS_UNIX_USER (user_of_subject) && polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_of_subject)) == 0)
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

  result_details = polkit_details_new ();

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
      result = polkit_authorization_result_new (TRUE, FALSE, result_details);
      goto out;
    }

  /* then see if there's a temporary authorization for the subject */
  if (temporary_authorization_store_has_authorization (priv->temporary_authorization_store,
                                                       subject,
                                                       action_id,
                                                       &tmp_authz_id))
    {

      g_debug (" is authorized (has temporary authorization)");
      polkit_details_insert (result_details, "polkit.temporary_authorization_id", tmp_authz_id);
      result = polkit_authorization_result_new (TRUE, FALSE, result_details);
      goto out;
    }

  if (implicit_authorization != POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED)
    {
      if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED ||
          implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
        {
          polkit_details_insert (result_details, "polkit.retains_authorization_after_challenge", "1");
        }

      result = polkit_authorization_result_new (FALSE, TRUE, result_details);

      /* return implicit_authorization so the caller can use an authentication agent if applicable */
      if (out_implicit_authorization != NULL)
        *out_implicit_authorization = implicit_authorization;

      g_debug (" challenge (implicit_authorization = %s)",
               polkit_implicit_authorization_to_string (implicit_authorization));
    }
  else
    {
      result = polkit_authorization_result_new (FALSE, FALSE, result_details);
      g_debug (" not authorized");
    }
 out:
  g_free (subject_str);

  g_list_foreach (groups_of_user, (GFunc) g_object_unref, NULL);
  g_list_free (groups_of_user);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);

  if (session_for_subject != NULL)
    g_object_unref (session_for_subject);

  if (action_desc != NULL)
    g_object_unref (action_desc);

  if (result_details != NULL)
    g_object_unref (result_details);

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
 * @action_id: The action we are about to authenticate for.
 * @details: Details about the action.
 *
 * Gets a list of identities to use for administrator authentication.
 *
 * The default implementation returns a list with a single element for the super user.
 *
 * Returns: A list of #PolkitIdentities. Free each element
 *     g_object_unref(), then free the list with g_list_free().
 */
GList *
polkit_backend_interactive_authority_get_admin_identities (PolkitBackendInteractiveAuthority *authority,
                                                           PolkitSubject                     *caller,
                                                           PolkitSubject                     *subject,
                                                           PolkitIdentity                    *user_for_subject,
                                                           const gchar                       *action_id,
                                                           PolkitDetails                     *details)
{
  PolkitBackendInteractiveAuthorityClass *klass;
  GList *ret;

  klass = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_CLASS (authority);

  if (klass->get_admin_identities == NULL)
    {
      ret = g_list_prepend (NULL, polkit_unix_user_new (0));
    }
  else
    {
      ret = klass->get_admin_identities (authority,
                                         caller,
                                         subject,
                                         user_for_subject,
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
 * specified by @action_id and @details.
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

struct AuthenticationAgent
{
  PolkitSubject *session;

  gchar *locale;
  gchar *object_path;
  gchar *unique_system_bus_name;

  EggDBusObjectProxy *object_proxy;

  GList *active_sessions;
};

struct AuthenticationSession
{
  AuthenticationAgent         *agent;

  gchar                       *cookie;

  PolkitSubject               *subject;

  PolkitIdentity              *user_of_subject;

  PolkitBackendInteractiveAuthority *authority;

  GList                       *identities;

  gchar                       *action_id;

  gchar                       *initiated_by_system_bus_unique_name;

  PolkitImplicitAuthorization  implicit_authorization;

  AuthenticationAgentCallback  callback;

  gpointer                     user_data;

  guint                        call_id;

  gboolean                     is_authenticated;

  GCancellable                *cancellable;

  gulong                       cancellable_signal_handler_id;
};

static void
authentication_session_cancelled_cb (GCancellable *cancellable,
                                     AuthenticationSession *session)
{
  authentication_session_cancel (session);
}

static AuthenticationSession *
authentication_session_new (AuthenticationAgent         *agent,
                            const gchar                 *cookie,
                            PolkitSubject               *subject,
                            PolkitIdentity              *user_of_subject,
                            PolkitBackendInteractiveAuthority *authority,
                            GList                       *identities,
                            const gchar                 *action_id,
                            const gchar                 *initiated_by_system_bus_unique_name,
                            PolkitImplicitAuthorization  implicit_authorization,
                            GCancellable                *cancellable,
                            AuthenticationAgentCallback  callback,
                            gpointer                     user_data)
{
  AuthenticationSession *session;

  session = g_new0 (AuthenticationSession, 1);
  session->agent = agent;
  session->cookie = g_strdup (cookie);
  session->subject = g_object_ref (subject);
  session->user_of_subject = g_object_ref (user_of_subject);
  session->authority = g_object_ref (authority);
  session->identities = g_list_copy (identities);
  g_list_foreach (session->identities, (GFunc) g_object_ref, NULL);
  session->action_id = g_strdup (action_id);
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
  g_free (session->cookie);
  g_list_foreach (session->identities, (GFunc) g_object_unref, NULL);
  g_list_free (session->identities);
  g_object_unref (session->subject);
  g_object_unref (session->user_of_subject);
  g_object_unref (session->authority);
  g_free (session->action_id);
  g_free (session->initiated_by_system_bus_unique_name);
  if (session->cancellable_signal_handler_id > 0)
    g_signal_handler_disconnect (session->cancellable, session->cancellable_signal_handler_id);
  if (session->cancellable != NULL)
    g_object_unref (session->cancellable);
  g_free (session);
}

static gchar *
authentication_agent_new_cookie (AuthenticationAgent *agent)
{
  static gint counter = 0;

  /* TODO: use a more random-looking cookie */

  return g_strdup_printf ("cookie%d", counter++);
}

static PolkitSubject *
authentication_agent_get_session (AuthenticationAgent *agent)
{
  return agent->session;
}

static void
authentication_agent_free (AuthenticationAgent *agent)
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

  g_object_unref (agent->object_proxy);

  g_object_unref (agent->session);
  g_free (agent->locale);
  g_free (agent->object_path);
  g_free (agent->unique_system_bus_name);
  g_free (agent);
}

static AuthenticationAgent *
authentication_agent_new (PolkitSubject *session,
                          const gchar *unique_system_bus_name,
                          const gchar *locale,
                          const gchar *object_path)
{
  AuthenticationAgent *agent;
  EggDBusConnection *system_bus;

  agent = g_new0 (AuthenticationAgent, 1);

  agent->session = g_object_ref (session);
  agent->object_path = g_strdup (object_path);
  agent->unique_system_bus_name = g_strdup (unique_system_bus_name);
  agent->locale = g_strdup (locale);

  system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  agent->object_proxy = egg_dbus_connection_get_object_proxy (system_bus,
                                                              agent->unique_system_bus_name,
                                                              agent->object_path);

  g_object_unref (system_bus);

  return agent;
}

static AuthenticationAgent *
get_authentication_agent_for_subject (PolkitBackendInteractiveAuthority *authority,
                                      PolkitSubject *subject)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_subject;
  AuthenticationAgent *agent;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  agent = NULL;
  session_for_subject = NULL;

  session_for_subject = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                                subject,
                                                                                NULL);
  if (session_for_subject == NULL)
    goto out;

  agent = g_hash_table_lookup (priv->hash_session_to_authentication_agent, session_for_subject);

 out:
  if (session_for_subject != NULL)
    g_object_unref (session_for_subject);

  return agent;
}

static AuthenticationSession *
get_authentication_session_for_cookie (PolkitBackendInteractiveAuthority *authority,
                                       const gchar *cookie)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  GHashTableIter hash_iter;
  AuthenticationAgent *agent;
  AuthenticationSession *result;

  result = NULL;

  /* TODO: perhaps use a hash on the cookie to speed this up */

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  g_hash_table_iter_init (&hash_iter, priv->hash_session_to_authentication_agent);
  while (g_hash_table_iter_next (&hash_iter, NULL, (gpointer) &agent))
    {
      GList *l;

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

  g_hash_table_iter_init (&hash_iter, priv->hash_session_to_authentication_agent);
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

  g_hash_table_iter_init (&hash_iter, priv->hash_session_to_authentication_agent);
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

  g_hash_table_iter_init (&hash_iter, priv->hash_session_to_authentication_agent);
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
authentication_agent_begin_callback (GObject *source_object,
                                     GAsyncResult *res,
                                     gpointer user_data)
{
  _PolkitAuthenticationAgent *agent_dbus = _POLKIT_AUTHENTICATION_AGENT (source_object);
  AuthenticationSession *session = user_data;
  GError *error;
  gboolean gained_authorization;

  error = NULL;
  if (!_polkit_authentication_agent_begin_authentication_finish (agent_dbus,
                                                                 res,
                                                                 &error))
    {
      g_warning ("Error performing authentication: %s", error->message);
      g_error_free (error);
      gained_authorization = FALSE;
    }
  else
    {
      gained_authorization = session->is_authenticated;

      g_debug ("Authentication complete, is_authenticated = %d", session->is_authenticated);
    }

  session->agent->active_sessions = g_list_remove (session->agent->active_sessions, session);

  session->callback (session->agent,
                     session->subject,
                     session->user_of_subject,
                     session->authority,
                     session->action_id,
                     session->implicit_authorization,
                     gained_authorization,
                     session->user_data);

  authentication_session_free (session);
}

static GList *
get_action_lookup_list (void)
{
  GList *extensions;
  GList *l;
  GIOExtensionPoint *action_lookup_ep;
  static GList *action_lookup_list = NULL;
  static gboolean have_looked_up_extensions = FALSE;

  if (have_looked_up_extensions)
    goto out;

  action_lookup_ep = g_io_extension_point_lookup (POLKIT_BACKEND_ACTION_LOOKUP_EXTENSION_POINT_NAME);
  g_assert (action_lookup_ep != NULL);

  extensions = g_io_extension_point_get_extensions (action_lookup_ep);
  for (l = extensions; l != NULL; l = l->next)
    {
      GIOExtension *extension = l->data;
      PolkitBackendActionLookup *lookup;

      lookup = g_object_new (g_io_extension_get_type (extension), NULL);
      action_lookup_list = g_list_prepend (action_lookup_list, lookup);
    }
  action_lookup_list = g_list_reverse (action_lookup_list);

 out:
  have_looked_up_extensions = TRUE;
  return action_lookup_list;
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
                                  EggDBusHashMap             **out_localized_details)
{
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitActionDescription *action_desc;
  GList *action_lookup_list;
  GList *l;
  gchar *message;
  gchar *icon_name;
  PolkitDetails *localized_details;

  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (authority);

  message = NULL;
  icon_name = NULL;
  localized_details = NULL;
  action_desc = NULL;

  *out_localized_message = NULL;
  *out_localized_icon_name = NULL;
  *out_localized_details = egg_dbus_hash_map_new (G_TYPE_STRING, NULL,
                                                  G_TYPE_STRING, NULL);

  action_desc = polkit_backend_action_pool_get_action (priv->action_pool,
                                                       action_id,
                                                       locale);
  if (action_desc == NULL)
    goto out;

  /* Set LANG and locale so gettext() + friends work when running the code in the extensions */
  if (setlocale (LC_ALL, locale) == NULL)
    {
      g_warning ("Invalid locale '%s'", locale);
    }
  g_setenv ("LANG", locale, TRUE);

  /* call into extension points to get localized auth dialog data - the list is sorted by priority */
  action_lookup_list = get_action_lookup_list ();
  for (l = action_lookup_list; l != NULL; l = l->next)
    {
      PolkitBackendActionLookup *lookup = POLKIT_BACKEND_ACTION_LOOKUP (l->data);

      if (message != NULL && icon_name != NULL && localized_details != NULL)
        break;

      if (message == NULL)
        message = polkit_backend_action_lookup_get_message (lookup,
                                                            action_id,
                                                            details,
                                                            action_desc);

      if (icon_name == NULL)
        icon_name = polkit_backend_action_lookup_get_icon_name (lookup,
                                                                action_id,
                                                                details,
                                                                action_desc);

      if (localized_details == NULL)
        localized_details = polkit_backend_action_lookup_get_details (lookup,
                                                                      action_id,
                                                                      details,
                                                                      action_desc);
    }

  /* Back to C! */
  setlocale (LC_ALL, "C");
  g_setenv ("LANG", "C", TRUE);

  /* fall back to action description */
  if (message == NULL)
    {
      message = g_strdup (polkit_action_description_get_message (action_desc));
    }
  if (icon_name == NULL)
    {
      icon_name = g_strdup (polkit_action_description_get_icon_name (action_desc));
    }


  if (localized_details != NULL)
    {
      GHashTable *hash;
      GHashTableIter iter;
      const gchar *key;
      const gchar *value;

      hash = polkit_details_get_hash (localized_details);
      if (hash != NULL)
        {
          g_hash_table_iter_init (&iter, hash);
          while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value))
            {
              egg_dbus_hash_map_insert (*out_localized_details, key, value);
            }
        }
    }

 out:
  if (message == NULL)
    message = g_strdup ("");
  if (icon_name == NULL)
    icon_name = g_strdup ("");
  *out_localized_message = message;
  *out_localized_icon_name = icon_name;
  if (action_desc != NULL)
    g_object_unref (action_desc);
}

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
  AuthenticationSession *session;
  _PolkitAuthenticationAgent *agent_dbus;
  gchar *cookie;
  GList *l;
  GList *identities;
  EggDBusArraySeq *real_identities;
  gchar *localized_message;
  gchar *localized_icon_name;
  EggDBusHashMap *localized_details;

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

  cookie = authentication_agent_new_cookie (agent);

  identities = NULL;

  /* select admin user if required by the implicit authorization */
  if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED ||
      implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
    {
      identities = polkit_backend_interactive_authority_get_admin_identities (authority,
                                                                              caller,
                                                                              subject,
                                                                              user_of_subject,
                                                                              action_id,
                                                                              details);
    }
  else
    {
      identities = g_list_prepend (identities, g_object_ref (user_of_subject));
    }

  session = authentication_session_new (agent,
                                        cookie,
                                        subject,
                                        user_of_subject,
                                        authority,
                                        identities,
                                        action_id,
                                        polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                        implicit_authorization,
                                        cancellable,
                                        callback,
                                        user_data);

  agent->active_sessions = g_list_prepend (agent->active_sessions, session);

  agent_dbus = _POLKIT_QUERY_INTERFACE_AUTHENTICATION_AGENT (agent->object_proxy);

  real_identities = egg_dbus_array_seq_new (EGG_DBUS_TYPE_STRUCTURE, g_object_unref, NULL, NULL);
  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      egg_dbus_array_seq_add (real_identities, polkit_identity_get_real (identity));
    }

  session->call_id = _polkit_authentication_agent_begin_authentication (agent_dbus,
                                                                        EGG_DBUS_CALL_FLAGS_TIMEOUT_NONE,
                                                                        action_id,
                                                                        localized_message,
                                                                        localized_icon_name,
                                                                        localized_details,
                                                                        session->cookie,
                                                                        real_identities,
                                                                        NULL,
                                                                        authentication_agent_begin_callback,
                                                                        session);

  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);
  g_object_unref (real_identities);
  g_free (cookie);

  g_free (localized_message);
  g_free (localized_icon_name);
  g_object_unref (localized_details);
}

static void
authentication_agent_cancel_callback (GObject *source_object,
                                      GAsyncResult *res,
                                      gpointer user_data)
{
  _PolkitAuthenticationAgent *agent_dbus = _POLKIT_AUTHENTICATION_AGENT (source_object);

  _polkit_authentication_agent_cancel_authentication_finish (agent_dbus,
                                                             res,
                                                             NULL);
}

static void
authentication_session_cancel (AuthenticationSession *session)
{
  EggDBusConnection *system_bus;
  _PolkitAuthenticationAgent *agent_dbus;

  system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  agent_dbus = _POLKIT_QUERY_INTERFACE_AUTHENTICATION_AGENT (session->agent->object_proxy);

  _polkit_authentication_agent_cancel_authentication (agent_dbus,
                                                      EGG_DBUS_CALL_FLAGS_NONE,
                                                      session->cookie,
                                                      NULL,
                                                      authentication_agent_cancel_callback,
                                                      NULL);

  egg_dbus_connection_pending_call_cancel (system_bus, session->call_id);

  g_object_unref (system_bus);
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_backend_interactive_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                                    PolkitSubject            *caller,
                                                                    PolkitSubject            *subject,
                                                                    const gchar              *locale,
                                                                    const gchar              *object_path,
                                                                    GError                  **error)
{
  PolkitBackendInteractiveAuthority *interactive_authority;
  PolkitBackendInteractiveAuthorityPrivate *priv;
  PolkitSubject *session_for_caller;
  AuthenticationAgent *agent;
  gboolean ret;

  session_for_caller = NULL;
  ret = FALSE;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  if (!POLKIT_IS_UNIX_SESSION (subject))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Can only register PolkitUnixSession objects for now.");
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

  agent = g_hash_table_lookup (priv->hash_session_to_authentication_agent, session_for_caller);
  if (agent != NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "An authentication agent already exists for session");
      goto out;
    }

  /* TODO: validate that object path is well-formed */

  agent = authentication_agent_new (session_for_caller,
                                    polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                    locale,
                                    object_path);

  g_hash_table_insert (priv->hash_session_to_authentication_agent,
                       g_object_ref (session_for_caller),
                       agent);

  g_debug ("Added authentication agent for session %s at name %s, object path %s, locale %s",
           polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session_for_caller)),
           polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
           object_path,
           locale);

  ret = TRUE;

 out:
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
  AuthenticationAgent *agent;
  gboolean ret;

  interactive_authority = POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority);
  priv = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_GET_PRIVATE (interactive_authority);

  ret = FALSE;
  session_for_caller = NULL;

  if (!POLKIT_IS_UNIX_SESSION (subject))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Can only unregister PolkitUnixSession objects for now.");
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

  agent = g_hash_table_lookup (priv->hash_session_to_authentication_agent, session_for_caller);
  if (agent == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "No such agent registered");
      goto out;
    }

  if (strcmp (agent->unique_system_bus_name,
              polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller))) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "System bus names do not match");
      goto out;
    }

  if (strcmp (agent->object_path, object_path) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Object paths do not match");
      goto out;
    }


  g_debug ("Removing authentication agent for session %s at name %s, object path %s (unregistered)",
           polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (agent->session)),
           agent->unique_system_bus_name,
           agent->object_path);

  /* this works because we have exactly one agent per session */
  g_hash_table_remove (priv->hash_session_to_authentication_agent, agent->session);

  ret = TRUE;

 out:
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_backend_interactive_authority_authentication_agent_response (PolkitBackendAuthority   *authority,
                                                              PolkitSubject            *caller,
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
                                                                        caller,
                                                                        error);
  if (user_of_caller == NULL)
    goto out;

  /* only uid 0 is allowed to invoke this method */
  if (!POLKIT_IS_UNIX_USER (user_of_caller) || polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_of_caller)) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Only uid 0 may invoke this method. This incident has been logged.");
      /* TODO: actually log this */
      goto out;
    }

  /* find the authentication session */
  session = get_authentication_session_for_cookie (interactive_authority, cookie);
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

  ret = TRUE;

 out:
  g_free (identity_str);

  if (user_of_caller != NULL)
    g_object_unref (user_of_caller);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_interactive_authority_system_bus_name_owner_changed (PolkitBackendAuthority   *authority,
                                                              const gchar              *name,
                                                              const gchar              *old_owner,
                                                              const gchar              *new_owner)
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
          g_debug ("Removing authentication agent for session %s at name %s, object path %s (disconnected from bus)",
                   polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (agent->session)),
                   agent->unique_system_bus_name,
                   agent->object_path);

          /* this works because we have exactly one agent per session */
          g_hash_table_remove (priv->hash_session_to_authentication_agent, agent->session);
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
  PolkitSubject *session;
  gchar *id;
  gchar *action_id;
  guint64 time_granted;
  guint64 time_expires;
  guint expiration_timeout_id;
  guint check_vanished_timeout_id;
};

static void
temporary_authorization_free (TemporaryAuthorization *authorization)
{
  g_free (authorization->id);
  g_object_unref (authorization->subject);
  g_object_unref (authorization->session);
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

  /* XXX: for now, prefer to store the process */
  if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      GError *error;
      error = NULL;
      subject_to_use = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                                NULL,
                                                                &error);
      if (subject_to_use == NULL)
        {
          g_warning ("Error getting process for system bus name `%s': %s",
                     polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                     error->message);
          g_error_free (error);
          subject_to_use = g_object_ref (subject);
        }
    }
  else
    {
      subject_to_use = g_object_ref (subject);
    }

  ret = FALSE;

  for (l = store->authorizations; l != NULL; l = l->next) {
    TemporaryAuthorization *authorization = l->data;

    if (strcmp (action_id, authorization->action_id) == 0 &&
        polkit_subject_equal (subject_to_use, authorization->subject))
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
          g_warning ("Error checking if process exists: %s", error->message);
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
                                                 PolkitSubject               *session,
                                                 const gchar                 *action_id)
{
  TemporaryAuthorization *authorization;
  guint expiration_seconds;
  PolkitSubject *subject_to_use;

  g_return_val_if_fail (store != NULL, NULL);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), NULL);
  g_return_val_if_fail (action_id != NULL, NULL);
  g_return_val_if_fail (!temporary_authorization_store_has_authorization (store, subject, action_id, NULL), NULL);

  /* XXX: for now, prefer to store the process */
  if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      GError *error;
      error = NULL;
      subject_to_use = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                                NULL,
                                                                &error);
      if (subject_to_use == NULL)
        {
          g_warning ("Error getting process for system bus name `%s': %s",
                     polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                     error->message);
          g_error_free (error);
          subject_to_use = g_object_ref (subject);
        }
    }
  else
    {
      subject_to_use = g_object_ref (subject);
    }

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
  authorization->session = g_object_ref (session);
  authorization->action_id = g_strdup (action_id);
  authorization->time_granted = time (NULL);
  authorization->time_expires = authorization->time_granted + expiration_seconds;
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

  for (l = priv->temporary_authorization_store->authorizations; l != NULL; l = l->next)
    {
      TemporaryAuthorization *ta = l->data;
      PolkitTemporaryAuthorization *tmp_authz;

      if (!polkit_subject_equal (ta->session, subject))
        continue;

      tmp_authz = polkit_temporary_authorization_new (ta->id,
                                                      ta->action_id,
                                                      ta->subject,
                                                      ta->time_granted,
                                                      ta->time_expires);

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

      if (!polkit_subject_equal (ta->session, subject))
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

      if (!polkit_subject_equal (session_for_caller, ta->session))
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

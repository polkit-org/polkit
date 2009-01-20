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

#include <polkit/polkit.h>
#include "polkitbackendlocalauthority.h"
#include "polkitbackendactionpool.h"
#include "polkitbackendpendingcall.h"
#include "polkitbackendsessionmonitor.h"

typedef struct
{
  PolkitBackendActionPool *action_pool;

  PolkitBackendSessionMonitor *session_monitor;

  GHashTable *hash_identity_to_authority_store;

  GHashTable *hash_session_to_authentication_agent;

} PolkitBackendLocalAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

struct AuthorizationStore;
typedef struct AuthorizationStore AuthorizationStore;

static void                authorization_store_free (AuthorizationStore *store);

static AuthorizationStore *get_authorization_store_for_identity (PolkitBackendLocalAuthority *authority,
                                                                 PolkitIdentity *identity);

/* ---------------------------------------------------------------------------------------------------- */

struct AuthenticationAgent;
typedef struct AuthenticationAgent AuthenticationAgent;

static void                authentication_agent_free (AuthenticationAgent *agent);

static AuthenticationAgent *get_authentication_agent_for_subject (PolkitBackendLocalAuthority *authority,
                                                                  PolkitSubject *subject);

/* ---------------------------------------------------------------------------------------------------- */

static gboolean check_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                                  PolkitIdentity              *identity,
                                                  const gchar                 *action_id);

static gboolean check_temporary_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                                           PolkitIdentity              *identity,
                                                           PolkitSubject               *subject,
                                                           const gchar                 *action_id);

static GList *get_groups_for_user (PolkitBackendLocalAuthority *authority,
                                   PolkitIdentity              *user);

static GList *get_authorizations_for_identity (PolkitBackendLocalAuthority *authority,
                                               PolkitIdentity              *identity);

static gboolean add_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                                PolkitIdentity              *identity,
                                                PolkitAuthorization         *authorization,
                                                GError                     **error);

static gboolean remove_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                                   PolkitIdentity              *identity,
                                                   PolkitAuthorization         *authorization,
                                                   GError                     **error);

/* ---------------------------------------------------------------------------------------------------- */

static void polkit_backend_local_authority_system_bus_name_owner_changed (PolkitBackendAuthority   *authority,
                                                                          const gchar              *name,
                                                                          const gchar              *old_owner,
                                                                          const gchar              *new_owner);

static void polkit_backend_local_authority_enumerate_actions  (PolkitBackendAuthority   *authority,
                                                               const gchar              *locale,
                                                               PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_enumerate_users    (PolkitBackendAuthority   *authority,
                                                               PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_enumerate_groups   (PolkitBackendAuthority   *authority,
                                                               PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_check_authorization (PolkitBackendAuthority        *authority,
                                                                PolkitSubject                 *subject,
                                                                const gchar                   *action_id,
                                                                PolkitCheckAuthorizationFlags  flags,
                                                                PolkitBackendPendingCall      *pending_call);

static PolkitAuthorizationResult check_authorization_sync (PolkitBackendAuthority         *authority,
                                                           PolkitSubject                  *subject,
                                                           const gchar                    *action_id,
                                                           PolkitCheckAuthorizationFlags   flags,
                                                           GError                        **error);

static void polkit_backend_local_authority_enumerate_authorizations (PolkitBackendAuthority   *authority,
                                                                     PolkitIdentity            *identity,
                                                                     PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_add_authorization (PolkitBackendAuthority   *authority,
                                                              PolkitIdentity           *identity,
                                                              PolkitAuthorization      *authorization,
                                                              PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_remove_authorization (PolkitBackendAuthority   *authority,
                                                                 PolkitIdentity           *identity,
                                                                 PolkitAuthorization      *authorization,
                                                                 PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                                          const gchar              *object_path,
                                                                          PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_unregister_authentication_agent (PolkitBackendAuthority   *authority,
                                                                            const gchar              *object_path,
                                                                            PolkitBackendPendingCall *pending_call);

/* ---------------------------------------------------------------------------------------------------- */

G_DEFINE_TYPE (PolkitBackendLocalAuthority, polkit_backend_local_authority, POLKIT_BACKEND_TYPE_AUTHORITY);

#define POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY, PolkitBackendLocalAuthorityPrivate))

static void
polkit_backend_local_authority_init (PolkitBackendLocalAuthority *local_authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  GFile *action_desc_directory;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  action_desc_directory = g_file_new_for_path (PACKAGE_DATA_DIR "/polkit-1/actions");
  priv->action_pool = polkit_backend_action_pool_new (action_desc_directory);
  g_object_unref (action_desc_directory);

  priv->hash_identity_to_authority_store = g_hash_table_new_full ((GHashFunc) polkit_identity_hash,
                                                                  (GEqualFunc) polkit_identity_equal,
                                                                  (GDestroyNotify) g_object_unref,
                                                                  (GDestroyNotify) authorization_store_free);

  priv->hash_session_to_authentication_agent = g_hash_table_new_full ((GHashFunc) polkit_subject_hash,
                                                                      (GEqualFunc) polkit_subject_equal,
                                                                      (GDestroyNotify) g_object_unref,
                                                                      (GDestroyNotify) authentication_agent_free);

  priv->session_monitor = polkit_backend_session_monitor_new ();
}

static void
polkit_backend_local_authority_finalize (GObject *object)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  if (priv->action_pool != NULL)
    g_object_unref (priv->action_pool);

  if (priv->session_monitor != NULL)
    g_object_unref (priv->session_monitor);

  g_hash_table_unref (priv->hash_identity_to_authority_store);

  g_hash_table_unref (priv->hash_session_to_authentication_agent);

  G_OBJECT_CLASS (polkit_backend_local_authority_parent_class)->finalize (object);
}

static void
polkit_backend_local_authority_class_init (PolkitBackendLocalAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);

  gobject_class->finalize = polkit_backend_local_authority_finalize;

  authority_class->system_bus_name_owner_changed   = polkit_backend_local_authority_system_bus_name_owner_changed;
  authority_class->enumerate_actions               = polkit_backend_local_authority_enumerate_actions;
  authority_class->enumerate_users                 = polkit_backend_local_authority_enumerate_users;
  authority_class->enumerate_groups                = polkit_backend_local_authority_enumerate_groups;
  authority_class->check_authorization             = polkit_backend_local_authority_check_authorization;
  authority_class->enumerate_authorizations        = polkit_backend_local_authority_enumerate_authorizations;
  authority_class->add_authorization               = polkit_backend_local_authority_add_authorization;
  authority_class->remove_authorization            = polkit_backend_local_authority_remove_authorization;
  authority_class->register_authentication_agent   = polkit_backend_local_authority_register_authentication_agent;
  authority_class->unregister_authentication_agent = polkit_backend_local_authority_unregister_authentication_agent;

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorityPrivate));
}

PolkitBackendAuthority *
polkit_backend_local_authority_new (void)
{
  return POLKIT_BACKEND_AUTHORITY (g_object_new (POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY,
                                                 NULL));
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                                  const gchar              *locale,
                                                  PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  GList *actions;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  actions = polkit_backend_action_pool_get_all_actions (priv->action_pool, locale);

  polkit_backend_authority_enumerate_actions_finish (pending_call,
                                                     actions);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_enumerate_users (PolkitBackendAuthority   *authority,
                                                PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  struct passwd *passwd;
  GList *list;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  list = NULL;

  passwd = getpwent ();
  if (passwd == NULL)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "getpwent failed: %s",
                                                strerror (errno));
      goto out;
    }

  do
    {
      PolkitIdentity *identity;

      identity = polkit_unix_user_new (passwd->pw_uid);

      list = g_list_prepend (list, identity);
    }
  while ((passwd = getpwent ()) != NULL);
  endpwent ();

  list = g_list_reverse (list);

  polkit_backend_authority_enumerate_users_finish (pending_call, list);

 out:
  ;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_enumerate_groups (PolkitBackendAuthority   *authority,
                                                 PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  struct group *group;
  GList *list;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  list = NULL;

  group = getgrent ();
  if (group == NULL)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "getpwent failed: %s",
                                                strerror (errno));
      goto out;
    }

  do
    {
      PolkitIdentity *identity;

      identity = polkit_unix_group_new (group->gr_gid);

      list = g_list_prepend (list, identity);
    }
  while ((group = getgrent ()) != NULL);
  endgrent ();

  list = g_list_reverse (list);

  polkit_backend_authority_enumerate_groups_finish (pending_call, list);

 out:
  ;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_check_authorization (PolkitBackendAuthority         *authority,
                                                    PolkitSubject                  *subject,
                                                    const gchar                    *action_id,
                                                    PolkitCheckAuthorizationFlags   flags,
                                                    PolkitBackendPendingCall       *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitSubject *inquirer;
  gchar *inquirer_str;
  gchar *subject_str;
  PolkitIdentity *user_of_inquirer;
  PolkitIdentity *user_of_subject;
  gchar *user_of_inquirer_str;
  gchar *user_of_subject_str;
  PolkitAuthorizationResult result;
  GError *error;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  error = NULL;
  inquirer = NULL;
  inquirer_str = NULL;
  subject_str = NULL;
  user_of_inquirer = NULL;
  user_of_subject = NULL;
  user_of_inquirer_str = NULL;
  user_of_subject_str = NULL;

  inquirer = polkit_backend_pending_call_get_caller (pending_call);

  inquirer_str = polkit_subject_to_string (inquirer);
  subject_str = polkit_subject_to_string (subject);

  g_debug ("%s is inquiring whether %s is authorized for %s",
           inquirer_str,
           subject_str,
           action_id);

  user_of_inquirer = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                          inquirer,
                                                                          &error);
  if (error != NULL)
    {
      polkit_backend_pending_call_return_gerror (pending_call, error);
      g_error_free (error);
      goto out;
    }

  user_of_inquirer_str = polkit_identity_to_string (user_of_inquirer);
  g_debug (" user of inquirer is %s", user_of_inquirer_str);

  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject,
                                                                         &error);
  if (error != NULL)
    {
      polkit_backend_pending_call_return_gerror (pending_call, error);
      g_error_free (error);
      goto out;
    }

  user_of_subject_str = polkit_identity_to_string (user_of_subject);
  g_debug (" user of subject is %s", user_of_subject_str);

  /* if the user of the inquirer and the user of the subject isn't the same, then
   * the org.freedesktop.policykit.read authorization is required for the inquirer
   */
  if (!polkit_identity_equal (user_of_inquirer, user_of_subject))
    {
      /* TODO */
      result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

      result = check_authorization_sync (authority,
                                         inquirer,
                                         "org.freedesktop.policykit.read",
                                         POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE, /* no user interaction */
                                         &error);

      if (error != NULL)
        {
          polkit_backend_pending_call_return_gerror (pending_call, error);
          g_error_free (error);
          goto out;
        }
      else if (result != POLKIT_AUTHORIZATION_RESULT_AUTHORIZED)
        {
          polkit_backend_pending_call_return_error (pending_call,
                                                    POLKIT_ERROR,
                                                    POLKIT_ERROR_NOT_AUTHORIZED,
                                                    "%s is not authorized to know about authorizations for %s (requires org.freedesktop.policykit.read authorization)",
                                                    inquirer_str,
                                                    subject_str);
          goto out;
        }
    }

  result = check_authorization_sync (authority, subject, action_id, flags, &error);
  if (error != NULL)
    {
      polkit_backend_pending_call_return_gerror (pending_call, error);
      g_error_free (error);
    }
  else
    {
      polkit_backend_authority_check_authorization_finish (pending_call, result);
    }

 out:

  if (user_of_inquirer != NULL)
    g_object_unref (user_of_inquirer);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);

  g_free (inquirer_str);
  g_free (subject_str);
  g_free (user_of_inquirer_str);
  g_free (user_of_subject_str);
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitAuthorizationResult
check_authorization_sync (PolkitBackendAuthority         *authority,
                          PolkitSubject                  *subject,
                          const gchar                    *action_id,
                          PolkitCheckAuthorizationFlags   flags,
                          GError                        **error)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitAuthorizationResult result;
  PolkitIdentity *user_of_subject;
  gchar *subject_str;
  GList *groups_of_user;
  GList *l;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

  user_of_subject = NULL;
  groups_of_user = NULL;
  subject_str = NULL;

  subject_str = polkit_subject_to_string (subject);

  g_debug ("checking whether %s is authorized for %s",
           subject_str,
           action_id);

  /* every subject has a user */
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject,
                                                                         error);
  if (user_of_subject == NULL)
      goto out;

  /* special case: uid 0, root, is _always_ authorized for anything */
  if (POLKIT_IS_UNIX_USER (user_of_subject) && polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_of_subject)) == 0)
    {
      result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
      goto out;
    }

  /* TODO: first see if there's an implicit authorization for subject available */

  /* then see if there's a temporary authorization for the subject */
  if (check_temporary_authorization_for_identity (local_authority, user_of_subject, subject, action_id))
    {
      g_debug (" is authorized (has temporary authorization)");
      result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
      goto out;
    }

  /* then see if we have an authorization for the user */
  if (check_authorization_for_identity (local_authority, user_of_subject, action_id))
    {
      g_debug (" is authorized (user identity has authorization)");
      result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
      goto out;
    }

  /* then see if we have a permanent authorization for any of the groups the user is in */
  groups_of_user = get_groups_for_user (local_authority, user_of_subject);
  for (l = groups_of_user; l != NULL; l = l->next)
    {
      PolkitIdentity *group = POLKIT_IDENTITY (l->data);

      if (check_authorization_for_identity (local_authority, group, action_id))
        {
          g_debug (" is authorized (group identity has authorization)");
          result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
          goto out;
        }
    }

  g_debug (" not authorized");

 out:
  g_free (subject_str);

  g_list_foreach (groups_of_user, (GFunc) g_object_unref, NULL);
  g_list_free (groups_of_user);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);

  g_debug (" ");

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_enumerate_authorizations (PolkitBackendAuthority   *authority,
                                                         PolkitIdentity           *identity,
                                                         PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  gchar *identity_str;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  identity_str = polkit_identity_to_string (identity);

  g_debug ("enumerating authorizations for %s", identity_str);

  /* TODO: check if caller is authorized */

  polkit_backend_authority_enumerate_authorizations_finish (pending_call,
                                                            get_authorizations_for_identity (local_authority,
                                                                                             identity));

  g_free (identity_str);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_add_authorization (PolkitBackendAuthority   *authority,
                                                  PolkitIdentity           *identity,
                                                  PolkitAuthorization      *authorization,
                                                  PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitSubject *subject;
  const gchar *action_id;
  gboolean is_negative;
  gchar *subject_str;
  GError *error;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  subject_str = NULL;
  error = NULL;

  subject = polkit_authorization_get_subject (authorization);
  action_id = polkit_authorization_get_action_id (authorization);
  is_negative = polkit_authorization_get_is_negative (authorization);

  if (subject != NULL)
    subject_str = polkit_subject_to_string (subject);

  g_debug ("add authorization with subject=%s, action_id=%s, is_negative=%d",
           subject_str != NULL ? subject_str : "<none>",
           action_id,
           is_negative);

  /* TODO: check if caller is authorized */

  /* We can only add temporary authorizations to users, not e.g. groups */
  if (subject != NULL && !POLKIT_IS_UNIX_USER (identity))
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "Can only add temporary authorizations to users");
      goto out;
    }

  if (!add_authorization_for_identity (local_authority,
                                       identity,
                                       authorization,
                                       &error))
    {
      polkit_backend_pending_call_return_gerror (pending_call, error);
      g_error_free (error);
    }
  else
    {
      polkit_backend_authority_add_authorization_finish (pending_call);
    }

 out:
  g_free (subject_str);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_remove_authorization (PolkitBackendAuthority   *authority,
                                                     PolkitIdentity           *identity,
                                                     PolkitAuthorization      *authorization,
                                                     PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitSubject *subject;
  const gchar *action_id;
  gboolean is_negative;
  gchar *subject_str;
  GError *error;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  subject_str = NULL;
  error = NULL;

  subject = polkit_authorization_get_subject (authorization);
  action_id = polkit_authorization_get_action_id (authorization);
  is_negative = polkit_authorization_get_is_negative (authorization);

  if (subject != NULL)
    subject_str = polkit_subject_to_string (subject);

  g_debug ("remove authorization with subject=%s, action_id=%s, is_negative=%d",
           subject_str != NULL ? subject_str : "<none>",
           action_id,
           is_negative);

  /* TODO: check if caller is authorized */

  /* We can only remove temporary authorizations to users, not e.g. groups */
  if (subject != NULL && !POLKIT_IS_UNIX_USER (identity))
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "Can only remove temporary authorizations from users");
      goto out;
    }

  if (!remove_authorization_for_identity (local_authority,
                                          identity,
                                          authorization,
                                          &error))
    {
      polkit_backend_pending_call_return_gerror (pending_call, error);
      g_error_free (error);
    }
  else
    {
      polkit_backend_authority_remove_authorization_finish (pending_call);
    }

 out:

  g_free (subject_str);
}

/* ---------------------------------------------------------------------------------------------------- */

struct AuthenticationAgent
{
  PolkitSubject *session;

  gchar *object_path;
  gchar *unique_system_bus_name;
};

static void
authentication_agent_free (AuthenticationAgent *agent)
{
  g_object_unref (agent->session);
  g_free (agent->object_path);
  g_free (agent->unique_system_bus_name);
  g_free (agent);
}

static AuthenticationAgent *
authentication_agent_new (PolkitSubject *session,
                          const gchar *unique_system_bus_name,
                          const gchar *object_path)
{
  AuthenticationAgent *agent;

  agent = g_new0 (AuthenticationAgent, 1);

  agent->session = g_object_ref (session);
  agent->object_path = g_strdup (object_path);
  agent->unique_system_bus_name = g_strdup (unique_system_bus_name);

  return agent;
}

static AuthenticationAgent *
get_authentication_agent_for_subject (PolkitBackendLocalAuthority *authority,
                                      PolkitSubject *subject)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitSubject *session_for_subject;
  AuthenticationAgent *agent;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

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
}

static AuthenticationAgent *
get_authentication_agent_by_unique_system_bus_name (PolkitBackendLocalAuthority *authority,
                                                    const gchar *unique_system_bus_name)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  GHashTableIter hash_iter;
  AuthenticationAgent *agent;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

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

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                              const gchar              *object_path,
                                                              PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitSubject *caller;
  PolkitSubject *session_for_caller;
  AuthenticationAgent *agent;

  session_for_caller = NULL;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  caller = polkit_backend_pending_call_get_caller (pending_call);

  session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                               caller,
                                                                               NULL);
  if (session_for_caller == NULL)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "Cannot determine session");
      goto out;
    }

  agent = g_hash_table_lookup (priv->hash_session_to_authentication_agent, session_for_caller);
  if (agent != NULL)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "An authentication agent already exists for session");
      goto out;
    }

  /* TODO: validate that object path is well-formed */

  agent = authentication_agent_new (session_for_caller,
                                    polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                    object_path);

  g_hash_table_insert (priv->hash_session_to_authentication_agent,
                       g_object_ref (session_for_caller),
                       agent);

  g_debug ("Added authentication agent for session %s at name %s, object path %s",
           polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session_for_caller)),
           polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
           object_path);

  polkit_backend_authority_register_authentication_agent_finish (pending_call);

 out:
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);
}

static void
polkit_backend_local_authority_unregister_authentication_agent (PolkitBackendAuthority   *authority,
                                                                const gchar              *object_path,
                                                                PolkitBackendPendingCall *pending_call)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitSubject *caller;
  PolkitSubject *session_for_caller;
  AuthenticationAgent *agent;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  caller = polkit_backend_pending_call_get_caller (pending_call);

  session_for_caller = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor,
                                                                               caller,
                                                                               NULL);
  if (session_for_caller == NULL)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "Cannot determine session");
      goto out;
    }

  agent = g_hash_table_lookup (priv->hash_session_to_authentication_agent, session_for_caller);
  if (agent == NULL)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "No such agent registered");
      goto out;
    }

  if (strcmp (agent->unique_system_bus_name,
              polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller))) != 0)
    {
      polkit_backend_pending_call_return_error (pending_call,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_FAILED,
                                                "System bus names do not match");
      goto out;
    }

  if (strcmp (agent->object_path, object_path) != 0)
    {
      polkit_backend_pending_call_return_error (pending_call,
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

  polkit_backend_authority_unregister_authentication_agent_finish (pending_call);

 out:
  if (session_for_caller != NULL)
    g_object_unref (session_for_caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authority_system_bus_name_owner_changed (PolkitBackendAuthority   *authority,
                                                              const gchar              *name,
                                                              const gchar              *old_owner,
                                                              const gchar              *new_owner)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  AuthenticationAgent *agent;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  //g_debug ("name-owner-changed: '%s' '%s' '%s'", name, old_owner, new_owner);

  if (name[0] == ':' && strlen (new_owner) == 0)
    {
      agent = get_authentication_agent_by_unique_system_bus_name (local_authority, name);
      if (agent != NULL)
        {
          g_debug ("Removing authentication agent for session %s at name %s, object path %s (disconnected from bus)",
                   polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (agent->session)),
                   agent->unique_system_bus_name,
                   agent->object_path);

          /* this works because we have exactly one agent per session */
          g_hash_table_remove (priv->hash_session_to_authentication_agent, agent->session);
        }
    }

}

/* ---------------------------------------------------------------------------------------------------- */

struct AuthorizationStore
{
  PolkitIdentity *identity;

  gchar *path;

  GList *authorizations;

  GList *temporary_authorizations;

};

static AuthorizationStore  *authorization_store_new (PolkitIdentity *identity);
static GList               *authorization_store_get_all_authorizations (AuthorizationStore *store);

static PolkitAuthorization *authorization_store_find_permanent_authorization (AuthorizationStore *store,
                                                                              const gchar *action_id);

static PolkitAuthorization *authorization_store_find_temporary_authorization (AuthorizationStore *store,
                                                                              PolkitSubject *subject,
                                                                              const gchar *action_id);

static gboolean             authorization_store_add_authorization (AuthorizationStore   *store,
                                                                   PolkitAuthorization  *authorization,
                                                                   GError              **error);

static gboolean             authorization_store_remove_authorization (AuthorizationStore   *store,
                                                                      PolkitAuthorization  *authorization,
                                                                      GError              **error);

/* private */
static void      authorization_store_reload_permanent_authorizations (AuthorizationStore   *store);
static gboolean  authorization_store_save_permanent_authorizations   (AuthorizationStore   *store,
                                                                      GError              **error);

static void
authorization_store_free (AuthorizationStore *store)
{
  g_object_unref (store->identity);
  g_list_foreach (store->authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (store->authorizations);
  g_list_foreach (store->temporary_authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (store->temporary_authorizations);
  g_free (store->path);
  g_free (store);
}

static AuthorizationStore *
authorization_store_new (PolkitIdentity *identity)
{
  AuthorizationStore *store;
  gchar *filename;
  gchar *identity_str;

  store = NULL;
  filename = NULL;

  identity_str = polkit_identity_to_string (identity);

  if (POLKIT_IS_UNIX_USER (identity))
    {
      filename = g_strdup_printf ("unix-user-%s.authz", identity_str + sizeof ("unix-user:") - 1);
    }
  else if (POLKIT_IS_UNIX_GROUP (identity))
    {
      filename = g_strdup_printf ("unix-group-%s.authz", identity_str + sizeof ("unix-group:") - 1);
    }
  else
    {
      g_error ("Unknown identity %s", identity_str);
      goto out;
    }

  store = g_new0 (AuthorizationStore, 1);
  store->identity = g_object_ref (identity);

  if (filename != NULL)
    store->path = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/%s", filename);

  authorization_store_reload_permanent_authorizations (store);

 out:
  g_free (filename);
  g_free (identity_str);
  return store;
}

static void
authorization_store_reload_permanent_authorizations (AuthorizationStore *store)
{
  GError *error;
  gchar *data;
  gchar **lines;
  gint n;

  error = NULL;
  data = NULL;

  g_list_foreach (store->authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (store->authorizations);
  store->authorizations = NULL;

  if (store->path == NULL)
    goto out;

  if (!g_file_get_contents (store->path,
                            &data,
                            NULL,
                            &error))
    {
      /* it's not a bug if the file doesn't exist */
      if (error->code != G_FILE_ERROR_NOENT)
        {
          g_warning ("Error loading authorizations file at %s: %s", store->path, error->message);
        }
      g_error_free (error);
      goto out;
    }

  lines = g_strsplit (data, "\n", 0);
  for (n = 0; lines[n] != NULL; n++)
    {
      gchar *line = lines[n];
      gchar **tokens;
      guint num_tokens;
      const gchar *action_id;
      gboolean is_negative;
      PolkitAuthorization *authorization;

      /* skip blank lines and comments */
      if (strlen (line) == 0 || line[0] == '#')
        continue;

      tokens = g_strsplit (line, " ", 0);
      num_tokens = g_strv_length (tokens);

      if (num_tokens != 2)
        {
          g_warning ("Malformed authorizations line '%s' in file %s at line %d", line, store->path, n);
          g_strfreev (tokens);
          continue;
        }

      action_id = tokens[0];
      is_negative = (strcmp (tokens[1], "1") == 0);

      authorization = polkit_authorization_new (action_id, NULL, is_negative);

      store->authorizations = g_list_prepend (store->authorizations, authorization);
    }
  g_strfreev (lines);

  store->authorizations = g_list_reverse (store->authorizations);

 out:
  g_free (data);
}

static gboolean
authorization_store_save_permanent_authorizations (AuthorizationStore  *store,
                                                   GError             **error)
{
  GString *s;
  gchar *str;
  GList *l;
  gboolean ret;

  ret = FALSE;
  str = NULL;

  /* simply unlink the file if there are no authorizations */
  if (store->authorizations == NULL)
    {
      if (g_unlink (store->path) != 0)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot remove authorization. Error unlinking file %s: %m",
                       store->path);
          goto out;
        }

      ret = TRUE;
      goto out;
    }

  s = g_string_new ("# polkit-1 " PACKAGE_VERSION " authorizations file\n"
                    "#\n"
                    "# Do not edit, use polkit-1(1) to manipulate authorizations\n"
                    "#\n"
                    "\n");

  for (l = store->authorizations; l != NULL; l = l->next)
    {
      PolkitAuthorization *authorization = POLKIT_AUTHORIZATION (l->data);
      const gchar *action_id;
      gboolean is_negative;

      action_id = polkit_authorization_get_action_id (authorization);
      is_negative = polkit_authorization_get_is_negative (authorization);

      g_string_append_printf (s, "%s %d\n", action_id, is_negative);
    }

  str = g_string_free (s, FALSE);

  if (!g_file_set_contents (store->path,
                            str,
                            strlen (str),
                            error))
    goto out;

  ret = TRUE;

 out:

  g_free (str);

  return ret;
}


/* caller must free list after unreffing all elements */
static GList *
authorization_store_get_all_authorizations (AuthorizationStore *store)
{
  GList *result;

  result = g_list_copy (store->authorizations);
  result = g_list_concat (result, g_list_copy (store->temporary_authorizations));

  g_list_foreach (result, (GFunc) g_object_ref, NULL);

  return result;
}

static PolkitAuthorization *
authorization_store_find_permanent_authorization (AuthorizationStore *store,
                                                  const gchar *action_id)
{
  GList *l;
  PolkitAuthorization *ret;

  ret = NULL;

  for (l = store->authorizations; l != NULL; l = l->next)
    {
      PolkitAuthorization *authorization = POLKIT_AUTHORIZATION (l->data);
      const gchar *authorization_action_id;

      authorization_action_id = polkit_authorization_get_action_id (authorization);
      if (strcmp (authorization_action_id, action_id) == 0)
        {
          ret = authorization;
          goto out;
        }
    }

 out:
  return ret;
}

static PolkitAuthorization *
authorization_store_find_temporary_authorization (AuthorizationStore *store,
                                                  PolkitSubject *subject,
                                                  const gchar *action_id)
{
  GList *l;
  PolkitAuthorization *ret;

  ret = NULL;

  for (l = store->temporary_authorizations; l != NULL; l = l->next)
    {
      PolkitAuthorization *authorization = POLKIT_AUTHORIZATION (l->data);
      const gchar *authorization_action_id;
      PolkitSubject *authorization_subject;

      authorization_action_id = polkit_authorization_get_action_id (authorization);
      authorization_subject = polkit_authorization_get_subject (authorization);

      if (strcmp (authorization_action_id, action_id) == 0 &&
          polkit_subject_equal (authorization_subject, subject))
        {
          ret = authorization;
          goto out;
        }
    }

 out:
  return ret;
}

static gboolean
authorization_store_add_authorization (AuthorizationStore   *store,
                                       PolkitAuthorization  *authorization,
                                       GError              **error)
{
  gboolean ret;
  PolkitSubject *subject;
  const gchar *action_id;

  ret = FALSE;

  action_id = polkit_authorization_get_action_id (authorization);
  subject = polkit_authorization_get_subject (authorization);

  if (subject != NULL)
    {
      /* check if authorization is already present */
      if (authorization_store_find_temporary_authorization (store, subject, action_id) != NULL)
        {
          gchar *subject_str;

          subject_str = polkit_subject_to_string (subject);

          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot add authorization. Identity already has an authorization for %s for the subject %s",
                       action_id,
                       subject_str);

          g_free (subject_str);
          goto out;
        }

      store->temporary_authorizations = g_list_prepend (store->temporary_authorizations, g_object_ref (authorization));

      ret = TRUE;
    }
  else
    {
      /* check if authorization is already present */
      if (authorization_store_find_permanent_authorization (store, action_id) != NULL)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot add authorization. Identity already has an authorization for %s", action_id);
          goto out;
        }

      store->authorizations = g_list_prepend (store->authorizations, g_object_ref (authorization));

      if (!authorization_store_save_permanent_authorizations (store, error))
        {
          /* roll back then */
          store->authorizations = g_list_remove (store->authorizations, authorization);
          g_object_unref (authorization);
          goto out;
        }

      ret = TRUE;
    }

 out:
  return ret;
}

static gboolean
authorization_store_remove_authorization (AuthorizationStore   *store,
                                          PolkitAuthorization  *authorization,
                                          GError              **error)
{
  gboolean ret;
  PolkitSubject *subject;
  const gchar *action_id;
  PolkitAuthorization *target;

  ret = FALSE;

  action_id = polkit_authorization_get_action_id (authorization);
  subject = polkit_authorization_get_subject (authorization);

  if (subject != NULL)
    {

      target = authorization_store_find_temporary_authorization (store, subject, action_id);

      if (target == NULL)
        {
          gchar *subject_str;

          subject_str = polkit_subject_to_string (subject);

          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot remove authorization. Identity doesn't has an authorization for %s constrained to the subject %s", action_id, subject_str);

          g_free (subject_str);
          goto out;
        }

      store->temporary_authorizations = g_list_remove (store->temporary_authorizations, target);

      ret = TRUE;

      goto out;
    }
  else
    {
      GList *old_list;

      target = authorization_store_find_permanent_authorization (store, action_id);

      if (target == NULL)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot remove authorization. Identity doesn't has an authorization for %s", action_id);
          goto out;
        }

      old_list = g_list_copy (store->authorizations);

      store->authorizations = g_list_remove (store->authorizations, target);

      if (!authorization_store_save_permanent_authorizations (store, error))
        {
          /* roll back then */
          g_list_free (store->authorizations);
          store->authorizations = old_list;
          goto out;
        }

      g_object_unref (target);

      ret = TRUE;
    }

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static AuthorizationStore *
get_authorization_store_for_identity (PolkitBackendLocalAuthority *authority,
                                      PolkitIdentity *identity)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  AuthorizationStore *store;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  store = g_hash_table_lookup (priv->hash_identity_to_authority_store, identity);
  if (store != NULL)
    goto out;

  store = authorization_store_new (identity);
  if (store == NULL)
    goto out;

  g_hash_table_insert (priv->hash_identity_to_authority_store,
                       g_object_ref (identity),
                       store);

 out:
  return store;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
check_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                  PolkitIdentity              *identity,
                                  const gchar                 *action_id)
{
  AuthorizationStore *store;
  gboolean result;

  result = FALSE;

  store = get_authorization_store_for_identity (authority, identity);
  if (store == NULL)
    goto out;

  result = (authorization_store_find_permanent_authorization (store, action_id) != NULL);

 out:
  return result;
}

static gboolean
check_temporary_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                            PolkitIdentity              *identity,
                                            PolkitSubject               *subject,
                                            const gchar                 *action_id)
{
  AuthorizationStore *store;
  gboolean result;

  result = FALSE;

  store = get_authorization_store_for_identity (authority, identity);
  if (store == NULL)
    goto out;

  result = (authorization_store_find_temporary_authorization (store, subject, action_id) != NULL);

 out:
  return result;
}

static GList *
get_groups_for_user (PolkitBackendLocalAuthority *authority,
                     PolkitIdentity              *user)
{
  uid_t uid;
  struct passwd *passwd;
  GList *result;
  gid_t groups[512];
  int num_groups = 512;
  int n;

  result = NULL;

  /* TODO: it would be, uhm, good to cache this information */

  uid = polkit_unix_user_get_uid (POLKIT_UNIX_USER (user));
  passwd = getpwuid (uid);
  if (passwd == NULL)
    {
      g_warning ("No user with uid %d", uid);
      goto out;
    }

  /* TODO: should resize etc etc etc */

  if (getgrouplist (passwd->pw_name,
                    passwd->pw_gid,
                    groups,
                    &num_groups) < 0)
    {
      g_warning ("Error looking up groups for uid %d: %m", uid);
      goto out;
    }

  for (n = 0; n < num_groups; n++)
    result = g_list_prepend (result, polkit_unix_group_new (groups[n]));

 out:

  return result;
}

static GList *
get_authorizations_for_identity (PolkitBackendLocalAuthority *authority,
                                 PolkitIdentity              *identity)
{
  AuthorizationStore *store;
  GList *result;

  result = NULL;

  store = get_authorization_store_for_identity (authority, identity);
  if (store == NULL)
    goto out;

  result = authorization_store_get_all_authorizations (store);

 out:
  return result;
}

static gboolean
add_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                PolkitIdentity              *identity,
                                PolkitAuthorization         *authorization,
                                GError                     **error)
{
  AuthorizationStore *store;
  gboolean ret;

  ret = FALSE;

  store = get_authorization_store_for_identity (authority, identity);
  if (store == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Malformed identity");
      goto out;
    }

  ret = authorization_store_add_authorization (store,
                                               authorization,
                                               error);

 out:
  return ret;
}

static gboolean
remove_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                   PolkitIdentity              *identity,
                                   PolkitAuthorization         *authorization,
                                   GError                     **error)
{
  AuthorizationStore *store;
  gboolean ret;

  ret = FALSE;

  store = get_authorization_store_for_identity (authority, identity);
  if (store == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Malformed identity");
      goto out;
    }

  ret = authorization_store_remove_authorization (store,
                                                  authorization,
                                                  error);

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

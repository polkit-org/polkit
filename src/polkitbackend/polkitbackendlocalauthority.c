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
#include <polkit/polkit.h>
#include "polkitbackendlocalauthority.h"
#include "polkitbackendactionpool.h"
#include "polkitbackendpendingcall.h"
#include "polkitbackendsessionmonitor.h"

typedef struct
{
  PolkitBackendActionPool *action_pool;

  PolkitBackendSessionMonitor *session_monitor;

} PolkitBackendLocalAuthorityPrivate;

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

  authority_class->enumerate_actions        = polkit_backend_local_authority_enumerate_actions;
  authority_class->enumerate_users          = polkit_backend_local_authority_enumerate_users;
  authority_class->enumerate_groups         = polkit_backend_local_authority_enumerate_groups;
  authority_class->check_authorization      = polkit_backend_local_authority_check_authorization;
  authority_class->enumerate_authorizations = polkit_backend_local_authority_enumerate_authorizations;
  authority_class->add_authorization        = polkit_backend_local_authority_add_authorization;
  authority_class->remove_authorization     = polkit_backend_local_authority_remove_authorization;

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
#if 0
      result = check_authorization_sync (authority,
                                         user_of_inquirer,
                                         "org.freedesktop.policykit.read",
                                         POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE, /* no user interaction */
                                         &error);
#endif

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
                                                    user_of_inquirer_str,
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

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;
  user_of_subject = NULL;
  subject_str = NULL;

  subject_str = polkit_subject_to_string (subject);

  g_debug ("checking whether %s is authorized for %s",
           subject_str,
           action_id);

  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject,
                                                                         error);
  if (user_of_subject == NULL)
      goto out;

  if (POLKIT_IS_UNIX_USER (user_of_subject) && polkit_unix_user_get_uid (POLKIT_UNIX_USER (user_of_subject)) == 0)
    {
      /* uid 0, root, is _always_ authorized for anything */
      result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
      goto out;
    }

#if 0
  g_set_error (error,
               POLKIT_ERROR,
               POLKIT_ERROR_NOT_SUPPORTED,
               "Not implemented (subject=%s action_id=%s)",
               subject_str, action_id);
#endif

  /* TODO */
  result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

 out:
  g_free (subject_str);

  if (user_of_subject != NULL)
    g_object_unref (user_of_subject);

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

  polkit_backend_pending_call_return_error (pending_call,
                                            POLKIT_ERROR,
                                            POLKIT_ERROR_NOT_SUPPORTED,
                                            "Not implemented (identity=%s)", identity_str);

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

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  subject_str = NULL;

  subject = polkit_authorization_get_subject (authorization);
  action_id = polkit_authorization_get_action_id (authorization);
  is_negative = polkit_authorization_get_is_negative (authorization);

  if (subject != NULL)
    subject_str = polkit_subject_to_string (subject);

  g_debug ("add authorization with subject=%s, action_id=%s, is_negative=%d",
           subject_str != NULL ? subject_str : "<none>",
           action_id,
           is_negative);

  polkit_backend_pending_call_return_error (pending_call,
                                            POLKIT_ERROR,
                                            POLKIT_ERROR_NOT_SUPPORTED,
                                            "Not implemented (subject=%s action_id=%s is_negative=%d)",
                                            subject_str, action_id, is_negative);

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

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  subject_str = NULL;

  subject = polkit_authorization_get_subject (authorization);
  action_id = polkit_authorization_get_action_id (authorization);
  is_negative = polkit_authorization_get_is_negative (authorization);

  if (subject != NULL)
    subject_str = polkit_subject_to_string (subject);

  g_debug ("remove authorization with subject=%s, action_id=%s, is_negative=%d",
           subject_str != NULL ? subject_str : "<none>",
           action_id,
           is_negative);

  polkit_backend_pending_call_return_error (pending_call,
                                            POLKIT_ERROR,
                                            POLKIT_ERROR_NOT_SUPPORTED,
                                            "Not implemented (subject=%s action_id=%s is_negative=%d)",
                                            subject_str, action_id, is_negative);

  g_free (subject_str);
}

/* ---------------------------------------------------------------------------------------------------- */

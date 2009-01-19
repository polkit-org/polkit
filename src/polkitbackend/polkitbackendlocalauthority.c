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

  GHashTable *hash_identity_to_authority_store;

} PolkitBackendLocalAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

struct AuthorizationStore;
typedef struct AuthorizationStore AuthorizationStore;

static AuthorizationStore *authorization_store_new (PolkitIdentity *identity);

static void                authorization_store_free (AuthorizationStore *store);

static GList              *authorization_store_get_all_authorizations (AuthorizationStore *store);

/* ---------------------------------------------------------------------------------------------------- */

static AuthorizationStore *get_authorization_store_for_identity (PolkitBackendLocalAuthority *authority,
                                                                 PolkitIdentity *identity);

/* ---------------------------------------------------------------------------------------------------- */

static gboolean check_authorization_for_identity (PolkitBackendLocalAuthority *authority,
                                                  PolkitIdentity              *identity,
                                                  const gchar                 *action_id);

static gboolean check_temporary_authorization_for_subject (PolkitBackendLocalAuthority *authority,
                                                           PolkitSubject               *subject,
                                                           const gchar                 *action_id);

static GList *get_groups_for_user (PolkitBackendLocalAuthority *authority,
                                   PolkitIdentity              *user);

static GList *get_authorizations_for_identity (PolkitBackendLocalAuthority *authority,
                                               PolkitIdentity              *identity);

/* ---------------------------------------------------------------------------------------------------- */

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
  if (check_temporary_authorization_for_subject (local_authority, subject, action_id))
    {
      result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
      goto out;
    }

  /* then see if we have an authorization for the user */
  if (check_authorization_for_identity (local_authority, user_of_subject, action_id))
    {
      result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
      goto out;
    }

  /* then see if we have an authorization for any of the groups the user is in */
  groups_of_user = get_groups_for_user (local_authority, user_of_subject);
  for (l = groups_of_user; l != NULL; l = l->next)
    {
      PolkitIdentity *group = POLKIT_IDENTITY (l->data);

      if (check_authorization_for_identity (local_authority, group, action_id))
        {
          result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
          goto out;
        }
    }

#if 0
  g_set_error (error,
               POLKIT_ERROR,
               POLKIT_ERROR_NOT_SUPPORTED,
               "Not implemented (subject=%s action_id=%s)",
               subject_str, action_id);
#endif

  /* TODO */

 out:
  g_free (subject_str);

  g_list_foreach (groups_of_user, (GFunc) g_object_unref, NULL);
  g_list_free (groups_of_user);

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

  /* TODO: check caller is authorized */

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

struct AuthorizationStore
{
  PolkitIdentity *identity;

  gchar *path;

  GList *authorizations;

  GList *temporary_authorizations;

};

/* private */
static void  authorization_store_reload_permanent_authorizations (AuthorizationStore *store);

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

 out:
  g_free (data);
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
  /* TODO */
  return FALSE;
}

static gboolean
check_temporary_authorization_for_subject (PolkitBackendLocalAuthority *authority,
                                           PolkitSubject               *subject,
                                           const gchar                 *action_id)
{
  /* TODO */
  return FALSE;
}

static GList *
get_groups_for_user (PolkitBackendLocalAuthority *authority,
                     PolkitIdentity              *user)
{
  /* TODO */
  return NULL;
}

static GList *
get_authorizations_for_identity (PolkitBackendLocalAuthority *authority,
                                 PolkitIdentity              *identity)
{
  AuthorizationStore *store;
  GList *result;

  store = get_authorization_store_for_identity (authority, identity);
  if (store == NULL)
    goto out;

  result = authorization_store_get_all_authorizations (store);

 out:
  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

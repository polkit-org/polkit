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
#include <glib/gi18n-lib.h>

#include <polkit/polkit.h>
#include "polkitbackendconfigsource.h"
#include "polkitbackendlocalauthority.h"
#include "polkitbackendlocalauthorizationstore.h"
#include "polkitbackendactionlookup.h"

#include <polkit/polkitprivate.h>

/**
 * SECTION:polkitbackendlocalauthority
 * @title: PolkitBackendLocalAuthority
 * @short_description: Local Authority
 * @stability: Unstable
 *
 * An implementation of #PolkitBackendAuthority that stores
 * authorizations on the local file system, supports interaction with
 * authentication agents (virtue of being based on
 * #PolkitBackendInteractiveAuthority), and implements support for
 * lock down.
 */

/* ---------------------------------------------------------------------------------------------------- */

static GList *get_users_in_group (PolkitIdentity              *group,
                                  gboolean                     include_root);

static GList *get_groups_for_user (PolkitIdentity              *user);

static void register_extensions (void);

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  PolkitBackendConfigSource *config_source;

  GList *authorization_stores;

} PolkitBackendLocalAuthorityPrivate;

/* ---------------------------------------------------------------------------------------------------- */

static GList *polkit_backend_local_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *authority,
                                                                        PolkitSubject                     *caller,
                                                                        PolkitSubject                     *subject,
                                                                        PolkitIdentity                    *user_for_subject,
                                                                        const gchar                       *action_id,
                                                                        PolkitDetails                     *details);

static PolkitImplicitAuthorization polkit_backend_local_authority_check_authorization_sync (
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

static void polkit_backend_local_authority_add_lockdown_for_action (PolkitBackendAuthority  *authority,
                                                                    PolkitSubject           *caller,
                                                                    const gchar             *action_id,
                                                                    GAsyncReadyCallback      callback,
                                                                    gpointer                 user_data);

static gboolean polkit_backend_local_authority_add_lockdown_for_action_finish (PolkitBackendAuthority  *authority,
                                                                               GAsyncResult            *res,
                                                                               GError                 **error);

static void polkit_backend_local_authority_remove_lockdown_for_action (PolkitBackendAuthority  *authority,
                                                                       PolkitSubject           *caller,
                                                                       const gchar             *action_id,
                                                                       GAsyncReadyCallback      callback,
                                                                       gpointer                 user_data);

static gboolean polkit_backend_local_authority_remove_lockdown_for_action_finish (PolkitBackendAuthority  *authority,
                                                                                  GAsyncResult            *res,
                                                                                  GError                 **error);


G_DEFINE_TYPE_WITH_CODE (PolkitBackendLocalAuthority,
                         polkit_backend_local_authority,
                         POLKIT_BACKEND_TYPE_INTERACTIVE_AUTHORITY,
                         g_io_extension_point_implement (POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME,
                                                         g_define_type_id,
                                                         "local-authority" PACKAGE_VERSION,
                                                         0));

#define POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY, PolkitBackendLocalAuthorityPrivate))

/* ---------------------------------------------------------------------------------------------------- */

static void
on_store_changed (PolkitBackendLocalAuthorizationStore *store,
                  gpointer                              user_data)
{
  PolkitBackendLocalAuthority *authority = POLKIT_BACKEND_LOCAL_AUTHORITY (user_data);

  g_signal_emit_by_name (authority, "changed");
}

static void
polkit_backend_local_authority_init (PolkitBackendLocalAuthority *authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  GFile *directory;
  guint n;
  const gchar *store_locations[] =
    {
      PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority/10-vendor.d",
      PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority/20-org.d",
      PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority/30-site.d",
      PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority/50-local.d",
      PACKAGE_LOCALSTATE_DIR "/lib/polkit-1/localauthority/90-mandatory.d",
      NULL
    };

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  directory = g_file_new_for_path (PACKAGE_SYSCONF_DIR "/polkit-1/localauthority.conf.d");
  priv->config_source = polkit_backend_config_source_new (directory);
  g_object_unref (directory);

  for (n = 0; store_locations[n] != NULL; n++)
    {
      PolkitBackendLocalAuthorizationStore *store;

      directory = g_file_new_for_path (store_locations[n]);
      store = polkit_backend_local_authorization_store_new (directory, ".pkla");
      priv->authorization_stores = g_list_prepend (priv->authorization_stores, store);
      g_object_unref (directory);

      g_signal_connect (store,
                        "changed",
                        G_CALLBACK (on_store_changed),
                        authority);
    }
  priv->authorization_stores = g_list_reverse (priv->authorization_stores);
}

static void
polkit_backend_local_authority_finalize (GObject *object)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (object);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  if (priv->config_source != NULL)
    g_object_unref (priv->config_source);

  g_list_foreach (priv->authorization_stores, (GFunc) g_object_unref, NULL);
  g_list_free (priv->authorization_stores);

  G_OBJECT_CLASS (polkit_backend_local_authority_parent_class)->finalize (object);
}

static const gchar *
polkit_backend_local_authority_get_name (PolkitBackendAuthority *authority)
{
  return "local";
}

static const gchar *
polkit_backend_local_authority_get_version (PolkitBackendAuthority *authority)
{
  return PACKAGE_VERSION;
}

static PolkitAuthorityFeatures
polkit_backend_local_authority_get_features (PolkitBackendAuthority *authority)
{
  return POLKIT_AUTHORITY_FEATURES_TEMPORARY_AUTHORIZATION | POLKIT_AUTHORITY_FEATURES_LOCKDOWN;
}

static void
polkit_backend_local_authority_class_init (PolkitBackendLocalAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;
  PolkitBackendInteractiveAuthorityClass *interactive_authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);
  interactive_authority_class = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_CLASS (klass);

  gobject_class->finalize                               = polkit_backend_local_authority_finalize;
  authority_class->get_name                             = polkit_backend_local_authority_get_name;
  authority_class->get_version                          = polkit_backend_local_authority_get_version;
  authority_class->get_features                         = polkit_backend_local_authority_get_features;
  authority_class->add_lockdown_for_action              = polkit_backend_local_authority_add_lockdown_for_action;
  authority_class->add_lockdown_for_action_finish       = polkit_backend_local_authority_add_lockdown_for_action_finish;
  authority_class->remove_lockdown_for_action           = polkit_backend_local_authority_remove_lockdown_for_action;
  authority_class->remove_lockdown_for_action_finish    = polkit_backend_local_authority_remove_lockdown_for_action_finish;
  interactive_authority_class->get_admin_identities     = polkit_backend_local_authority_get_admin_auth_identities;
  interactive_authority_class->check_authorization_sync = polkit_backend_local_authority_check_authorization_sync;

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorityPrivate));

  register_extensions ();
}

static GList *
polkit_backend_local_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *authority,
                                                          PolkitSubject                     *caller,
                                                          PolkitSubject                     *subject,
                                                          PolkitIdentity                    *user_for_subject,
                                                          const gchar                       *action_id,
                                                          PolkitDetails                     *details)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  GList *ret;
  guint n;
  gchar **admin_identities;
  GError *error;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  ret = NULL;

  error = NULL;
  admin_identities = polkit_backend_config_source_get_string_list (priv->config_source,
                                                                   "Configuration",
                                                                   "AdminIdentities",
                                                                   &error);
  if (admin_identities == NULL)
    {
      g_warning ("Error getting admin_identities configuration item: %s", error->message);
      g_error_free (error);
      goto out;
    }

  for (n = 0; admin_identities[n] != NULL; n++)
    {
      PolkitIdentity *identity;

      error = NULL;
      identity = polkit_identity_from_string (admin_identities[n], &error);
      if (identity == NULL)
        {
          g_warning ("Error parsing identity %s: %s", admin_identities[n], error->message);
          g_error_free (error);
          continue;
        }

      if (POLKIT_IS_UNIX_USER (identity))
        {
          ret = g_list_append (ret, identity);
        }
      else if (POLKIT_IS_UNIX_GROUP (identity))
        {
          ret = g_list_concat (ret, get_users_in_group (identity, FALSE));
        }
      else
        {
          g_warning ("Unsupported identity %s", admin_identities[n]);
        }
    }

  g_strfreev (admin_identities);

 out:

  /* default to uid 0 if no admin identities has been found */
  if (ret == NULL)
    ret = g_list_prepend (ret, polkit_unix_user_new (0));

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitImplicitAuthorization
polkit_backend_local_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *authority,
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
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  PolkitImplicitAuthorization ret;
  PolkitImplicitAuthorization ret_any;
  PolkitImplicitAuthorization ret_inactive;
  PolkitImplicitAuthorization ret_active;
  GList *groups;
  GList *l, *ll;

  ret = implicit;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

#if 0
  g_debug ("local: checking `%s' for subject `%s' (user `%s')",
           action_id,
           polkit_subject_to_string (subject),
           polkit_identity_to_string (user_for_subject));
#endif

  /* First lookup for all groups the user belong to */
  groups = get_groups_for_user (user_for_subject);
  for (ll = groups; ll != NULL; ll = ll->next)
    {
      PolkitIdentity *group = POLKIT_IDENTITY (ll->data);

      for (l = priv->authorization_stores; l != NULL; l = l->next)
        {
          PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);

          if (polkit_backend_local_authorization_store_lookup (store,
                                                               group,
                                                               action_id,
                                                               details,
                                                               &ret_any,
                                                               &ret_inactive,
                                                               &ret_active,
                                                               out_details))
            {
              if (subject_is_local && subject_is_active)
                {
                  if (ret_active != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                    ret = ret_active;
                }
              else if (subject_is_local)
                {
                  if (ret_inactive != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                    ret = ret_inactive;
                }
              else
                {
                  if (ret_any != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                    ret = ret_any;
                }
            }
        }
    }
  g_list_foreach (groups, (GFunc) g_object_unref, NULL);
  g_list_free (groups);

  /* Then do it for the user */
  for (l = priv->authorization_stores; l != NULL; l = l->next)
    {
      PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (l->data);

      if (polkit_backend_local_authorization_store_lookup (store,
                                                           user_for_subject,
                                                           action_id,
                                                           details,
                                                           &ret_any,
                                                           &ret_inactive,
                                                           &ret_active,
                                                           out_details))
        {
          if (subject_is_local && subject_is_active)
            {
              if (ret_active != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                ret = ret_active;
            }
          else if (subject_is_local)
            {
              if (ret_inactive != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                ret = ret_inactive;
            }
          else
            {
              if (ret_any != POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN)
                ret = ret_any;
            }
        }
    }

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
get_users_in_group (PolkitIdentity                    *group,
                    gboolean                           include_root)
{
  gid_t gid;
  struct group *grp;
  GList *ret;
  guint n;

  ret = NULL;

  gid = polkit_unix_group_get_gid (POLKIT_UNIX_GROUP (group));
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

      if (!include_root && strcmp (grp->gr_mem[n], "root") == 0)
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
get_groups_for_user (PolkitIdentity *user)
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
      g_warning ("Error looking up groups for uid %d: %s", uid, g_strerror (errno));
      goto out;
    }

  for (n = 0; n < num_groups; n++)
    result = g_list_prepend (result, polkit_unix_group_new (groups[n]));

 out:

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static gchar *
lockdown_get_filename (const gchar *action_id)
{
  return g_strdup_printf (PACKAGE_LOCALSTATE_DIR
                          "/lib/polkit-1/localauthority/90-mandatory.d/"
                          "org.freedesktop.policykit.localauthority.lockdown.action-%s.pkla",
                          action_id);
}

static gboolean
lockdown_exists (const gchar *action_id)
{
  gchar *filename;
  gboolean ret;

  ret = FALSE;

  filename = lockdown_get_filename (action_id);
  if (g_file_test (filename, G_FILE_TEST_IS_REGULAR | G_FILE_TEST_EXISTS))
    ret = TRUE;
  g_free (filename);

  return ret;
}

static gboolean
lockdown_add (const gchar  *action_id,
              GError      **error)
{
  gboolean ret;
  gchar *filename;
  gchar *contents;

  ret = FALSE;

  filename = lockdown_get_filename (action_id);
  contents = g_strdup_printf ("# Added by pklalockdown(1)\n"
                              "#\n"
                              "[Lockdown]\n"
                              "Identity=unix-user:*\n"
                              "Action=%s\n"
                              "ResultAny=no\n"
                              "ResultInactive=no\n"
                              "ResultActive=auth_admin_keep\n"
                              "ReturnValue=polkit.lockdown=1",
                              action_id);
  if (!g_file_set_contents (filename,
                            contents,
                            -1,
                            error))
    goto out;

  ret = TRUE;

 out:
  g_free (filename);
  g_free (contents);
  return ret;
}

static gboolean
lockdown_remove (const gchar  *action_id,
                 GError      **error)
{
  gboolean ret;
  gchar *filename;

  ret = FALSE;

  filename = lockdown_get_filename (action_id);
  if (g_unlink (filename) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot unlink file %s: %s\n",
                   filename,
                   g_strerror (errno));
      goto out;
    }

  ret = TRUE;

 out:
  g_free (filename);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
add_lockdown_check_auth_cb (PolkitBackendAuthority *authority,
                            GAsyncResult           *res,
                            gpointer                user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  PolkitAuthorizationResult *result;
  GError *error;

  result = polkit_backend_authority_check_authorization_finish (authority,
                                                                res,
                                                                &error);
  if (result == NULL)
    {
      g_simple_async_result_set_from_error (simple, error);
      g_error_free (error);
    }
  else
    {
      if (polkit_authorization_result_get_is_authorized (result))
        {
          const gchar *action_id;

          action_id = g_object_get_data (G_OBJECT (simple), "lock-down-action-id");

          if (lockdown_exists (action_id))
            {
              g_simple_async_result_set_error (simple,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_FAILED,
                                               "Action %s is already locked down",
                                               action_id);
            }
          else
            {
              GError *error;

              error = NULL;
              if (!lockdown_add (action_id, &error))
                {
                  g_simple_async_result_set_error (simple,
                                                   POLKIT_ERROR,
                                                   POLKIT_ERROR_FAILED,
                                                   "Error adding lock down for action %s: %s",
                                                   action_id,
                                                   error->message);
                  g_error_free (error);
                }
            }
        }
      else
        {
          g_simple_async_result_set_error (simple,
                                           POLKIT_ERROR,
                                           POLKIT_ERROR_NOT_AUTHORIZED,
                                           "Not authorized to add lock down for the requested action");
        }
      g_object_unref (result);
    }

  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

static void
polkit_backend_local_authority_add_lockdown_for_action (PolkitBackendAuthority  *authority,
                                                        PolkitSubject           *caller,
                                                        const gchar             *action_id,
                                                        GAsyncReadyCallback      callback,
                                                        gpointer                 user_data)
{
  GSimpleAsyncResult *simple;
  PolkitDetails *details;
  GCancellable *cancellable;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_backend_local_authority_add_lockdown_for_action);

  g_object_set_data_full (G_OBJECT (simple), "lock-down-action-id", g_strdup (action_id), g_free);

  details = polkit_details_new ();
  polkit_details_insert (details, "action-id", action_id);
  polkit_details_insert (details, "add-lockdown", "1");

  cancellable = g_cancellable_new ();

  /* first check if caller is authorized for this */
  polkit_backend_authority_check_authorization (POLKIT_BACKEND_AUTHORITY (authority),
                                                NULL,
                                                caller,
                                                "org.freedesktop.policykit.lockdown",
                                                details,
                                                POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                                cancellable,
                                                (GAsyncReadyCallback) add_lockdown_check_auth_cb,
                                                simple);

  g_object_unref (details);
  g_object_unref (cancellable);
}

static gboolean
polkit_backend_local_authority_add_lockdown_for_action_finish (PolkitBackendAuthority  *authority,
                                                               GAsyncResult            *res,
                                                               GError                 **error)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_backend_local_authority_add_lockdown_for_action);

  if (g_simple_async_result_propagate_error (simple, error))
    return FALSE;

  return TRUE;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
remove_lockdown_check_auth_cb (PolkitBackendAuthority *authority,
                            GAsyncResult           *res,
                            gpointer                user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  PolkitAuthorizationResult *result;
  GError *error;

  result = polkit_backend_authority_check_authorization_finish (authority,
                                                                res,
                                                                &error);
  if (result == NULL)
    {
      g_simple_async_result_set_from_error (simple, error);
      g_error_free (error);
    }
  else
    {
      if (polkit_authorization_result_get_is_authorized (result))
        {
          const gchar *action_id;

          action_id = g_object_get_data (G_OBJECT (simple), "lock-down-action-id");

          if (!lockdown_exists (action_id))
            {
              g_simple_async_result_set_error (simple,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_FAILED,
                                               "Action %s is not locked down",
                                               action_id);
            }
          else
            {
              GError *error;

              error = NULL;
              if (!lockdown_remove (action_id, &error))
                {
                  g_simple_async_result_set_error (simple,
                                                   POLKIT_ERROR,
                                                   POLKIT_ERROR_FAILED,
                                                   "Error removing lock down for action %s: %s",
                                                   action_id,
                                                   error->message);
                  g_error_free (error);
                }
            }
        }
      else
        {
          g_simple_async_result_set_error (simple,
                                           POLKIT_ERROR,
                                           POLKIT_ERROR_NOT_AUTHORIZED,
                                           "Not authorized to remove lock down for the requested action");
        }
      g_object_unref (result);
    }

  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

static void
polkit_backend_local_authority_remove_lockdown_for_action (PolkitBackendAuthority  *authority,
                                                        PolkitSubject           *caller,
                                                        const gchar             *action_id,
                                                        GAsyncReadyCallback      callback,
                                                        gpointer                 user_data)
{
  GSimpleAsyncResult *simple;
  PolkitDetails *details;
  GCancellable *cancellable;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_backend_local_authority_remove_lockdown_for_action);

  g_object_set_data_full (G_OBJECT (simple), "lock-down-action-id", g_strdup (action_id), g_free);

  details = polkit_details_new ();
  polkit_details_insert (details, "action-id", action_id);
  polkit_details_insert (details, "remove-lockdown", "1");

  cancellable = g_cancellable_new ();

  /* first check if caller is authorized for this */
  polkit_backend_authority_check_authorization (POLKIT_BACKEND_AUTHORITY (authority),
                                                NULL,
                                                caller,
                                                "org.freedesktop.policykit.lockdown",
                                                details,
                                                POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                                cancellable,
                                                (GAsyncReadyCallback) remove_lockdown_check_auth_cb,
                                                simple);

  g_object_unref (details);
  g_object_unref (cancellable);
}

static gboolean
polkit_backend_local_authority_remove_lockdown_for_action_finish (PolkitBackendAuthority  *authority,
                                                               GAsyncResult            *res,
                                                               GError                 **error)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_backend_local_authority_remove_lockdown_for_action);

  if (g_simple_async_result_propagate_error (simple, error))
    return FALSE;

  return TRUE;
}

/* ---------------------------------------------------------------------------------------------------- */

#define PBLA_TYPE_ACTION_LOOKUP          (pbla_action_lookup_get_type())
#define PBLA_ACTION_LOOKUP(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), PBLA_TYPE_ACTION_LOOKUP, PblaActionLookup))
#define PBLA_ACTION_LOOKUP_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), PBLA_TYPE_ACTION_LOOKUP, PblaActionLookupClass))
#define PBLA_ACTION_LOOKUP_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), PBLA_TYPE_ACTION_LOOKUP, PblaActionLookupClass))
#define PBLA_IS_ACTION_LOOKUP(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), PBLA_TYPE_ACTION_LOOKUP))
#define PBLA_IS_ACTION_LOOKUP_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), PBLA_TYPE_ACTION_LOOKUP))

typedef struct _PblaActionLookup PblaActionLookup;
typedef struct _PblaActionLookupClass PblaActionLookupClass;

struct _PblaActionLookup
{
  GObject parent;
};

struct _PblaActionLookupClass
{
  GObjectClass parent_class;
};

GType pbla_action_lookup_get_type (void) G_GNUC_CONST;

static void pbla_action_lookup_iface_init (PolkitBackendActionLookupIface *iface);


G_DEFINE_TYPE_EXTENDED (PblaActionLookup,
                        pbla_action_lookup,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (POLKIT_BACKEND_TYPE_ACTION_LOOKUP,
                                               pbla_action_lookup_iface_init))

static void
pbla_action_lookup_init (PblaActionLookup *lookup)
{
}

static void
pbla_action_lookup_class_init (PblaActionLookupClass *klass)
{
}

/* ---------------------------------------------------------------------------------------------------- */

static gchar *
pbla_action_lookup_get_message   (PolkitBackendActionLookup *lookup,
                                  const gchar               *action_id,
                                  PolkitDetails             *details,
                                  PolkitActionDescription   *action_description)
{
  gchar *ret;
  const gchar *s;

  ret = NULL;

  if (g_strcmp0 (action_id, "org.freedesktop.policykit.lockdown") != 0)
    goto out;

  s = polkit_details_lookup (details, "remove-lockdown");
  if (s == NULL)
    {
      ret = g_strdup (_("Authentication is needed to lock down an action"));
    }
  else
    {
      ret = g_strdup (_("Authentication is needed to remove lock down for an action"));
    }

 out:
  return ret;
}

static gchar *
pbla_action_lookup_get_icon_name (PolkitBackendActionLookup *lookup,
                                  const gchar               *action_id,
                                  PolkitDetails             *details,
                                  PolkitActionDescription   *action_description)
{
  gchar *ret;

  ret = NULL;

  /* explicitly left blank for now */

  return ret;
}

static PolkitDetails *
pbla_action_lookup_get_details (PolkitBackendActionLookup *lookup,
                                const gchar               *action_id,
                                PolkitDetails             *details,
                                PolkitActionDescription   *action_desc)
{
  PolkitDetails *ret;
  const gchar *s;
  const gchar *s2;

  ret = NULL;

  if (g_strcmp0 (action_id, "org.freedesktop.policykit.lockdown") != 0)
    goto out;

  s = polkit_details_lookup (details, "action-id");
  if (s == NULL)
    goto out;

  s2 = polkit_details_lookup (details, "remove-lockdown");

  ret = polkit_details_new ();
  if (s2 == NULL)
    polkit_details_insert (ret, _("Action to lock down"), s);
  else
    polkit_details_insert (ret, _("Locked down action"), s);

 out:
  return ret;
}

static void
pbla_action_lookup_iface_init (PolkitBackendActionLookupIface *iface)
{
  iface->get_message   = pbla_action_lookup_get_message;
  iface->get_icon_name = pbla_action_lookup_get_icon_name;
  iface->get_details   = pbla_action_lookup_get_details;
}


static void
register_extensions (void)
{
  g_io_extension_point_implement (POLKIT_BACKEND_ACTION_LOOKUP_EXTENSION_POINT_NAME,
                                  PBLA_TYPE_ACTION_LOOKUP,
                                  "lockdown action lookup extension " PACKAGE_VERSION,
                                  0);
}

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
#include "polkitbackendconfigsource.h"
#include "polkitbackendlocalauthority.h"
#include "polkitbackendlocalauthorizationstore.h"

#include <polkit/polkitprivate.h>

/**
 * SECTION:polkitbackendlocalauthority
 * @title: PolkitBackendLocalAuthority
 * @short_description: Local Authority
 * @stability: Unstable
 *
 * An implementation of #PolkitBackendAuthority that stores authorizations on the local file system
 * and supports interaction with authentication agents.
 */

/* ---------------------------------------------------------------------------------------------------- */

static GList *get_users_in_group (PolkitIdentity              *group,
                                  gboolean                     include_root);

static GList *get_groups_for_user (PolkitIdentity              *user);

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
  interactive_authority_class->get_admin_identities     = polkit_backend_local_authority_get_admin_auth_identities;
  interactive_authority_class->check_authorization_sync = polkit_backend_local_authority_check_authorization_sync;

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorityPrivate));
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

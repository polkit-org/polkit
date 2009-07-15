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

static GList *get_users_in_group (PolkitBackendInteractiveAuthority *authority,
                                  PolkitIdentity              *group,
                                  gboolean                     include_root);

#if 0
static GList *get_groups_for_user (PolkitBackendInteractiveAuthority *authority,
                                   PolkitIdentity              *user);
#endif

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  PolkitBackendConfigSource *config_source;

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
                                                          const gchar                       *action_id,
                                                          PolkitDetails                     *details,
                                                          PolkitImplicitAuthorization        implicit);


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
polkit_backend_local_authority_init (PolkitBackendLocalAuthority *authority)
{
  PolkitBackendLocalAuthorityPrivate *priv;
  GFile *directory;

  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (authority);

  directory = g_file_new_for_path (PACKAGE_SYSCONF_DIR "/polkit-1/localauthority.conf.d");
  priv->config_source = polkit_backend_config_source_new (directory);
  g_object_unref (directory);
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

  G_OBJECT_CLASS (polkit_backend_local_authority_parent_class)->finalize (object);
}

static void
polkit_backend_local_authority_class_init (PolkitBackendLocalAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendInteractiveAuthorityClass *interactive_authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  interactive_authority_class = POLKIT_BACKEND_INTERACTIVE_AUTHORITY_CLASS (klass);

  gobject_class->finalize                               = polkit_backend_local_authority_finalize;
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
          ret = g_list_concat (ret, get_users_in_group (authority, identity, FALSE));
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
                                                         const gchar                       *action_id,
                                                         PolkitDetails                     *details,
                                                         PolkitImplicitAuthorization        implicit)
{
  g_debug ("local: checking `%s' for subject `%s' (user `%s')",
           action_id,
           polkit_subject_to_string (subject),
           polkit_identity_to_string (user_for_subject));

  return implicit;
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
get_users_in_group (PolkitBackendInteractiveAuthority *authority,
                    PolkitIdentity              *group,
                    gboolean                     include_root)
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
      g_warning ("Error looking up group with gid %d: %m", gid);
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

#if 0
static GList *
get_groups_for_user (PolkitBackendInteractiveAuthority *authority,
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
#endif

/* ---------------------------------------------------------------------------------------------------- */

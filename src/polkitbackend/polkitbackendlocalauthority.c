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

typedef struct
{
  PolkitBackendActionPool *action_pool;

} PolkitBackendLocalAuthorityPrivate;

static GList *polkit_backend_local_authority_enumerate_actions (PolkitBackendAuthority  *authority,
                                                                const gchar             *locale,
                                                                GError                 **error);

static GList *polkit_backend_local_authority_enumerate_users   (PolkitBackendAuthority  *authority,
                                                                GError                 **error);

static GList *polkit_backend_local_authority_enumerate_groups  (PolkitBackendAuthority  *authority,
                                                                GError                 **error);

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

  authority_class->enumerate_actions = polkit_backend_local_authority_enumerate_actions;
  authority_class->enumerate_users   = polkit_backend_local_authority_enumerate_users;
  authority_class->enumerate_groups  = polkit_backend_local_authority_enumerate_groups;

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorityPrivate));
}

PolkitBackendAuthority *
polkit_backend_local_authority_new (void)
{
  return POLKIT_BACKEND_AUTHORITY (g_object_new (POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY,
                                                 NULL));
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
polkit_backend_local_authority_enumerate_actions (PolkitBackendAuthority  *authority,
                                                  const gchar             *locale,
                                                  GError                 **error)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  return polkit_backend_action_pool_get_all_actions (priv->action_pool, locale);
}

static GList *
polkit_backend_local_authority_enumerate_users (PolkitBackendAuthority  *authority,
                                                GError                 **error)
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
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "getpwent failed: %s",
                   strerror (errno));
      goto out;
    }

  do
    {
      PolkitSubject *subject;

      subject = polkit_unix_user_new (passwd->pw_uid);

      list = g_list_prepend (list, subject);
    }
  while ((passwd = getpwent ()) != NULL);
  endpwent ();

  list = g_list_reverse (list);

 out:
  return list;
}

static GList *
polkit_backend_local_authority_enumerate_groups (PolkitBackendAuthority  *authority,
                                                 GError                 **error)
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
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "getgrent failed: %s",
                   strerror (errno));
      goto out;
    }

  do
    {
      PolkitSubject *subject;

      subject = polkit_unix_group_new (group->gr_gid);

      list = g_list_prepend (list, subject);
    }
  while ((group = getgrent ()) != NULL);
  endgrent ();

  list = g_list_reverse (list);

 out:
  return list;
}

#if 0
/* ---------------------------------------------------------------------------------------------------- */

static void
authority_iface_handle_say_hello (PolkitAuthority *authority,
                                  const gchar *message,
                                  EggDBusMethodInvocation *method_invocation)
{
  gchar *result;

  result = g_strdup_printf ("You said '%s' to the AUTHORITY!", message);

  polkit_authority_handle_say_hello_finish (method_invocation,
                                            result);

  g_free (result);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_iface_handle_enumerate_users (PolkitAuthority *authority,
                                        EggDBusMethodInvocation *method_invocation)
{
  struct passwd *passwd;
  GList *list;

  list = NULL;

  passwd = getpwent ();
  if (passwd == NULL)
    {
      egg_dbus_method_invocation_return_error (method_invocation,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_FAILED,
                                               "getpwent failed: %s",
                                               strerror (errno));
      goto out;
    }

  do
    {
      PolkitSubject *subject;

      subject = polkit_subject_new_for_unix_user (passwd->pw_uid);

      list = g_list_prepend (list, subject);
    }
  while ((passwd = getpwent ()) != NULL);
  endpwent ();

  list = g_list_reverse (list);

  polkit_authority_handle_enumerate_users_finish (method_invocation,
                                                  list);

 out:
  g_list_foreach (list, (GFunc) g_object_unref, NULL);
  g_list_free (list);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_iface_handle_enumerate_actions (PolkitAuthority         *authority,
                                          const gchar             *locale,
                                          EggDBusMethodInvocation *method_invocation)
{
  PolkitBackendLocalAuthority *local_authority;
  PolkitBackendLocalAuthorityPrivate *priv;
  GList *list;

  local_authority = POLKIT_BACKEND_LOCAL_AUTHORITY (authority);
  priv = POLKIT_BACKEND_LOCAL_AUTHORITY_GET_PRIVATE (local_authority);

  list = polkit_backend_action_pool_get_all_actions (priv->action_pool,
                                                     locale);

  polkit_authority_handle_enumerate_actions_finish (method_invocation,
                                                    list);

  g_list_foreach (list, (GFunc) g_object_unref, NULL);
  g_list_free (list);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_iface_init (PolkitAuthorityIface *authority_iface,
                      gpointer              iface_data)
{
  authority_iface->handle_say_hello          = authority_iface_handle_say_hello;
  authority_iface->handle_enumerate_users    = authority_iface_handle_enumerate_users;
  authority_iface->handle_enumerate_actions  = authority_iface_handle_enumerate_actions;
}

/* ---------------------------------------------------------------------------------------------------- */
#endif

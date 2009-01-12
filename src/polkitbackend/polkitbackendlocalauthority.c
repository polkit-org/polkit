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

typedef struct
{
  PolkitBackendActionPool *action_pool;

} PolkitBackendLocalAuthorityPrivate;

static void polkit_backend_local_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                                              const gchar              *locale,
                                                              PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_enumerate_users   (PolkitBackendAuthority   *authority,
                                                              PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_enumerate_groups  (PolkitBackendAuthority   *authority,
                                                              PolkitBackendPendingCall *pending_call);

static void polkit_backend_local_authority_check_claim       (PolkitBackendAuthority   *authority,
                                                              PolkitAuthorizationClaim *claim,
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
  authority_class->check_claim       = polkit_backend_local_authority_check_claim;

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
      PolkitSubject *subject;

      subject = polkit_unix_user_new (passwd->pw_uid);

      list = g_list_prepend (list, subject);
    }
  while ((passwd = getpwent ()) != NULL);
  endpwent ();

  list = g_list_reverse (list);

  polkit_backend_authority_enumerate_users_finish (pending_call, list);

 out:
  ;
}

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
      PolkitSubject *subject;

      subject = polkit_unix_group_new (group->gr_gid);

      list = g_list_prepend (list, subject);
    }
  while ((group = getgrent ()) != NULL);
  endgrent ();

  list = g_list_reverse (list);

  polkit_backend_authority_enumerate_groups_finish (pending_call, list);

 out:
  ;
}

static void
polkit_backend_local_authority_check_claim (PolkitBackendAuthority   *authority,
                                            PolkitAuthorizationClaim *claim,
                                            PolkitBackendPendingCall *pending_call)
{
  gchar *inquirer_str;
  gchar *subject_str;
  PolkitSubject *inquirer;
  PolkitSubject *subject;
  const gchar *action_id;

  inquirer = polkit_backend_pending_call_get_caller (pending_call);
  subject = polkit_authorization_claim_get_subject (claim);
  action_id = polkit_authorization_claim_get_action_id (claim);

  inquirer_str = polkit_subject_to_string (inquirer);
  subject_str = polkit_subject_to_string (subject);

  g_debug ("%s is inquiring whether %s is authorized for %s",
           inquirer_str,
           subject_str,
           action_id);

  polkit_backend_pending_call_return_error (pending_call,
                                            POLKIT_ERROR,
                                            POLKIT_ERROR_NOT_SUPPORTED,
                                            "Not implemented");

  g_free (inquirer_str);
  g_free (subject_str);
}


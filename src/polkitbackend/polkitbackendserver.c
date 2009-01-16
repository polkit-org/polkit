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
#include <string.h>
#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>

#include "polkitbackendauthority.h"
#include "polkitbackendserver.h"
#include "polkitbackendprivate.h"

struct _PolkitBackendServer
{
  GObject parent_instance;

  PolkitBackendAuthority *authority;
};

struct _PolkitBackendServerClass
{
  GObjectClass parent_class;
};

static void authority_iface_init (_PolkitAuthorityIface *authority_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitBackendServer, polkit_backend_server, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (_POLKIT_TYPE_AUTHORITY, authority_iface_init)
                         );

static void
polkit_backend_server_init (PolkitBackendServer *local_server)
{
}

static void
polkit_backend_server_finalize (GObject *object)
{
  PolkitBackendServer *server;

  server = POLKIT_BACKEND_SERVER (object);

  g_object_unref (server->authority);
}

static void
polkit_backend_server_class_init (PolkitBackendServerClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_backend_server_finalize;
}

PolkitBackendServer *
polkit_backend_server_new (PolkitBackendAuthority *authority)
{
  PolkitBackendServer *server;

  server = POLKIT_BACKEND_SERVER (g_object_new (POLKIT_BACKEND_TYPE_SERVER, NULL));

  server->authority = g_object_ref (authority);

  return server;
}

static void
authority_handle_enumerate_actions (_PolkitAuthority        *instance,
                                    const gchar             *locale,
                                    EggDBusMethodInvocation *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  polkit_backend_authority_enumerate_actions (server->authority, locale, pending_call);
}

void
polkit_backend_authority_enumerate_actions_finish (PolkitBackendPendingCall *pending_call,
                                                   GList                    *actions)
{
  EggDBusArraySeq *array;
  GList *l;

  array = egg_dbus_array_seq_new (_POLKIT_TYPE_ACTION_DESCRIPTION, (GDestroyNotify) g_object_unref, NULL, NULL);

  for (l = actions; l != NULL; l = l->next)
    {
      PolkitActionDescription *ad = POLKIT_ACTION_DESCRIPTION (l->data);
      _PolkitActionDescription *real;

      real = polkit_action_description_get_real (ad);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_handle_enumerate_actions_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                     array);

  g_object_unref (array);

  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  g_object_unref (pending_call);
}

static void
authority_handle_enumerate_users (_PolkitAuthority        *instance,
                                  EggDBusMethodInvocation *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  polkit_backend_authority_enumerate_users (server->authority, pending_call);
}

void
polkit_backend_authority_enumerate_users_finish (PolkitBackendPendingCall *pending_call,
                                                 GList                    *users)
{
  EggDBusArraySeq *array;
  GList *l;

  array = egg_dbus_array_seq_new (_POLKIT_TYPE_SUBJECT, (GDestroyNotify) g_object_unref, NULL, NULL);

  for (l = users; l != NULL; l = l->next)
    {
      PolkitSubject *subject = POLKIT_SUBJECT (l->data);
      _PolkitSubject *real;

      real = polkit_subject_get_real (subject);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_handle_enumerate_users_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                   array);

  g_object_unref (array);

  g_list_foreach (users, (GFunc) g_object_unref, NULL);
  g_list_free (users);

  g_object_unref (pending_call);
}

static void
authority_handle_enumerate_groups (_PolkitAuthority        *instance,
                                   EggDBusMethodInvocation *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  polkit_backend_authority_enumerate_groups (server->authority, pending_call);
}

void
polkit_backend_authority_enumerate_groups_finish (PolkitBackendPendingCall *pending_call,
                                                  GList                    *groups)
{
  EggDBusArraySeq *array;
  GList *l;

  array = egg_dbus_array_seq_new (_POLKIT_TYPE_SUBJECT, (GDestroyNotify) g_object_unref, NULL, NULL);

  for (l = groups; l != NULL; l = l->next)
    {
      PolkitSubject *subject = POLKIT_SUBJECT (l->data);
      _PolkitSubject *real;

      real = polkit_subject_get_real (subject);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_handle_enumerate_groups_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                    array);

  g_object_unref (array);

  g_list_foreach (groups, (GFunc) g_object_unref, NULL);
  g_list_free (groups);

  g_object_unref (pending_call);
}

static void
authority_handle_check_claim (_PolkitAuthority          *instance,
                              _PolkitAuthorizationClaim *real_claim,
                              EggDBusMethodInvocation   *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitAuthorizationClaim *claim;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  claim = polkit_authorization_claim_new_for_real (real_claim);

  g_object_set_data_full (G_OBJECT (pending_call), "claim", claim, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_check_claim (server->authority, claim, pending_call);
}

void
polkit_backend_authority_check_claim_finish (PolkitBackendPendingCall  *pending_call,
                                             PolkitAuthorizationResult  result)
{
  _polkit_authority_handle_check_claim_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                               result);

  g_object_unref (pending_call);
}

static void
authority_iface_init (_PolkitAuthorityIface *authority_iface)
{
  authority_iface->handle_enumerate_actions = authority_handle_enumerate_actions;
  authority_iface->handle_enumerate_users   = authority_handle_enumerate_users;
  authority_iface->handle_enumerate_groups  = authority_handle_enumerate_groups;
  authority_iface->handle_check_claim       = authority_handle_check_claim;
}

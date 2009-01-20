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

  EggDBusConnection *system_bus;

  EggDBusObjectProxy *bus_proxy;

  EggDBusBus *bus;

  gulong name_owner_changed_id;
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

  g_signal_handler_disconnect (server->bus, server->name_owner_changed_id);

  g_object_unref (server->bus_proxy);

  g_object_unref (server->system_bus);

  g_object_unref (server->authority);
}

static void
polkit_backend_server_class_init (PolkitBackendServerClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_backend_server_finalize;
}

static void
name_owner_changed (EggDBusBus *instance,
                    gchar      *name,
                    gchar      *old_owner,
                    gchar      *new_owner,
                    PolkitBackendServer *server)
{
  polkit_backend_authority_system_bus_name_owner_changed (server->authority, name, old_owner, new_owner);
}

PolkitBackendServer *
polkit_backend_server_new (PolkitBackendAuthority *authority)
{
  PolkitBackendServer *server;

  server = POLKIT_BACKEND_SERVER (g_object_new (POLKIT_BACKEND_TYPE_SERVER, NULL));

  server->authority = g_object_ref (authority);

  /* TODO: it's a bit wasteful listening to all name-owner-changed signals... needs to be optimized */

  server->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);
  server->bus_proxy = egg_dbus_connection_get_object_proxy (server->system_bus,
                                                            "org.freedesktop.DBus",
                                                            "/org/freedesktop/DBus");

  server->bus = EGG_DBUS_QUERY_INTERFACE_BUS (server->bus_proxy);

  server->name_owner_changed_id = g_signal_connect (server->bus,
                                                    "name-owner-changed",
                                                    (GCallback) name_owner_changed,
                                                    server);

  return server;
}

/* ---------------------------------------------------------------------------------------------------- */

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

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_ACTION_DESCRIPTION,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

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

/* ---------------------------------------------------------------------------------------------------- */

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

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_IDENTITY,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

  for (l = users; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      _PolkitIdentity *real;

      real = polkit_identity_get_real (identity);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_handle_enumerate_users_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                   array);

  g_object_unref (array);

  g_list_foreach (users, (GFunc) g_object_unref, NULL);
  g_list_free (users);

  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

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

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_IDENTITY,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

  for (l = groups; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      _PolkitIdentity *real;

      real = polkit_identity_get_real (identity);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_handle_enumerate_groups_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                    array);

  g_object_unref (array);

  g_list_foreach (groups, (GFunc) g_object_unref, NULL);
  g_list_free (groups);

  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_check_authorization (_PolkitAuthority               *instance,
                                      _PolkitSubject                 *real_subject,
                                      const gchar                    *action_id,
                                      _PolkitCheckAuthorizationFlags  flags,
                                      EggDBusMethodInvocation        *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitSubject *subject;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  subject = polkit_subject_new_for_real (real_subject);

  g_object_set_data_full (G_OBJECT (pending_call), "subject", subject, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_check_authorization (server->authority,
                                                subject,
                                                action_id,
                                                flags,
                                                pending_call);
}

void
polkit_backend_authority_check_authorization_finish (PolkitBackendPendingCall  *pending_call,
                                                     PolkitAuthorizationResult  result)
{
  _polkit_authority_handle_check_authorization_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                       result);

  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_enumerate_authorizations (_PolkitAuthority               *instance,
                                           _PolkitIdentity                 *real_identity,
                                           EggDBusMethodInvocation        *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  identity = polkit_identity_new_for_real (real_identity);

  g_object_set_data_full (G_OBJECT (pending_call), "identity", identity, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_enumerate_authorizations (server->authority,
                                                     identity,
                                                     pending_call);
}

void
polkit_backend_authority_enumerate_authorizations_finish (PolkitBackendPendingCall  *pending_call,
                                                          GList                     *authorizations)
{
  EggDBusArraySeq *array;
  GList *l;

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_AUTHORIZATION,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

  for (l = authorizations; l != NULL; l = l->next)
    {
      PolkitAuthorization *a = POLKIT_AUTHORIZATION (l->data);
      _PolkitAuthorization *real;

      real = polkit_authorization_get_real (a);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_handle_enumerate_authorizations_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                            array);

  g_object_unref (array);

  g_list_foreach (authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (authorizations);

  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_add_authorization (_PolkitAuthority               *instance,
                                    _PolkitIdentity                *real_identity,
                                    _PolkitAuthorization           *real_authorization,
                                    EggDBusMethodInvocation        *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;
  PolkitAuthorization *authorization;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  identity = polkit_identity_new_for_real (real_identity);

  authorization = polkit_authorization_new_for_real (real_authorization);

  g_object_set_data_full (G_OBJECT (pending_call), "identity", identity, (GDestroyNotify) g_object_unref);
  g_object_set_data_full (G_OBJECT (pending_call), "authorization", authorization, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_add_authorization (server->authority,
                                              identity,
                                              authorization,
                                              pending_call);
}

void
polkit_backend_authority_add_authorization_finish (PolkitBackendPendingCall  *pending_call)
{
  _polkit_authority_handle_add_authorization_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_remove_authorization (_PolkitAuthority               *instance,
                                       _PolkitIdentity                *real_identity,
                                       _PolkitAuthorization           *real_authorization,
                                       EggDBusMethodInvocation        *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;
  PolkitAuthorization *authorization;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  identity = polkit_identity_new_for_real (real_identity);

  authorization = polkit_authorization_new_for_real (real_authorization);

  g_object_set_data_full (G_OBJECT (pending_call), "identity", identity, (GDestroyNotify) g_object_unref);
  g_object_set_data_full (G_OBJECT (pending_call), "authorization", authorization, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_remove_authorization (server->authority,
                                                 identity,
                                                 authorization,
                                                 pending_call);
}

void
polkit_backend_authority_remove_authorization_finish (PolkitBackendPendingCall  *pending_call)
{
  _polkit_authority_handle_remove_authorization_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_register_authentication_agent (_PolkitAuthority               *instance,
                                                const gchar                    *object_path,
                                                EggDBusMethodInvocation        *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  polkit_backend_authority_register_authentication_agent (server->authority,
                                                          object_path,
                                                          pending_call);
}

void
polkit_backend_authority_register_authentication_agent_finish (PolkitBackendPendingCall  *pending_call)
{
  _polkit_authority_handle_register_authentication_agent_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_unregister_authentication_agent (_PolkitAuthority               *instance,
                                                  const gchar                    *object_path,
                                                  EggDBusMethodInvocation        *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation, server);

  polkit_backend_authority_unregister_authentication_agent (server->authority,
                                                          object_path,
                                                          pending_call);
}

void
polkit_backend_authority_unregister_authentication_agent_finish (PolkitBackendPendingCall  *pending_call)
{
  _polkit_authority_handle_unregister_authentication_agent_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_iface_init (_PolkitAuthorityIface *authority_iface)
{
  authority_iface->handle_enumerate_actions               = authority_handle_enumerate_actions;
  authority_iface->handle_enumerate_users                 = authority_handle_enumerate_users;
  authority_iface->handle_enumerate_groups                = authority_handle_enumerate_groups;
  authority_iface->handle_check_authorization             = authority_handle_check_authorization;
  authority_iface->handle_enumerate_authorizations        = authority_handle_enumerate_authorizations;
  authority_iface->handle_add_authorization               = authority_handle_add_authorization;
  authority_iface->handle_remove_authorization            = authority_handle_remove_authorization;
  authority_iface->handle_register_authentication_agent   = authority_handle_register_authentication_agent;
  authority_iface->handle_unregister_authentication_agent = authority_handle_unregister_authentication_agent;
}

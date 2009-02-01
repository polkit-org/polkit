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

#include "polkitbackendpendingcall.h"
#include "polkitbackendprivate.h"

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_ABSTRACT_TYPE (PolkitBackendAuthority, polkit_backend_authority, G_TYPE_OBJECT);

static void
polkit_backend_authority_init (PolkitBackendAuthority *local_authority)
{
}

static void
polkit_backend_authority_class_init (PolkitBackendAuthorityClass *klass)
{
  /**
   * PolkitBackendAuthority::changed:
   * @authority: A #PolkitBackendAuthority.
   *
   * Emitted when actions and/or authorizations change
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_BACKEND_TYPE_AUTHORITY,
                                          G_SIGNAL_RUN_LAST,
                                          0,                      /* class offset     */
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

void
polkit_backend_authority_system_bus_name_owner_changed (PolkitBackendAuthority   *authority,
                                                        const gchar              *name,
                                                        const gchar              *old_owner,
                                                        const gchar              *new_owner)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->system_bus_name_owner_changed (authority, name, old_owner, new_owner);
}

void
polkit_backend_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                            const gchar              *locale,
                                            PolkitBackendPendingCall *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_actions (authority, locale, pending_call);
}

void
polkit_backend_authority_enumerate_users (PolkitBackendAuthority   *authority,
                                          PolkitBackendPendingCall *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_users (authority, pending_call);
}

void
polkit_backend_authority_enumerate_groups (PolkitBackendAuthority   *authority,
                                           PolkitBackendPendingCall *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_groups (authority, pending_call);
}

void
polkit_backend_authority_check_authorization (PolkitBackendAuthority        *authority,
                                              PolkitSubject                 *subject,
                                              const gchar                   *action_id,
                                              PolkitCheckAuthorizationFlags  flags,
                                              PolkitBackendPendingCall      *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->check_authorization (authority, subject, action_id, flags, pending_call);
}

void
polkit_backend_authority_enumerate_authorizations  (PolkitBackendAuthority    *authority,
                                                    PolkitIdentity            *identity,
                                                    PolkitBackendPendingCall  *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_authorizations (authority, identity, pending_call);
}

void
polkit_backend_authority_add_authorization  (PolkitBackendAuthority    *authority,
                                             PolkitIdentity            *identity,
                                             PolkitAuthorization       *authorization,
                                             PolkitBackendPendingCall  *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->add_authorization (authority, identity, authorization, pending_call);
}

void
polkit_backend_authority_remove_authorization  (PolkitBackendAuthority    *authority,
                                                PolkitIdentity            *identity,
                                                PolkitAuthorization       *authorization,
                                                PolkitBackendPendingCall  *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->remove_authorization (authority, identity, authorization, pending_call);
}

void
polkit_backend_authority_register_authentication_agent (PolkitBackendAuthority    *authority,
                                                        const gchar               *object_path,
                                                        PolkitBackendPendingCall  *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->register_authentication_agent (authority, object_path, pending_call);
}

void
polkit_backend_authority_unregister_authentication_agent (PolkitBackendAuthority    *authority,
                                                          const gchar               *object_path,
                                                          PolkitBackendPendingCall  *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->unregister_authentication_agent (authority, object_path, pending_call);
}

void
polkit_backend_authority_authentication_agent_response (PolkitBackendAuthority    *authority,
                                                        const gchar               *cookie,
                                                        PolkitIdentity            *identity,
                                                        PolkitBackendPendingCall  *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->authentication_agent_response (authority, cookie, identity, pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

#define TYPE_SERVER         (server_get_type ())
#define SERVER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_SERVER, Server))
#define SERVER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), TYPE_SERVER, ServerClass))
#define SERVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_SERVER,ServerClass))
#define IS_SERVER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_SERVER))
#define IS_SERVER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_SERVER))

typedef struct _Server Server;
typedef struct _ServerClass ServerClass;

GType server_get_type (void) G_GNUC_CONST;

struct _Server
{
  GObject parent_instance;

  PolkitBackendAuthority *authority;

  EggDBusConnection *system_bus;

  EggDBusObjectProxy *bus_proxy;

  EggDBusBus *bus;

  gulong name_owner_changed_id;

  gulong authority_changed_id;

  gchar *well_known_name;
};

struct _ServerClass
{
  GObjectClass parent_class;
};

static void authority_iface_init         (_PolkitAuthorityIface        *authority_iface);
static void authority_manager_iface_init (_PolkitAuthorityManagerIface *authority_manager_iface);

G_DEFINE_TYPE_WITH_CODE (Server, server, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (_POLKIT_TYPE_AUTHORITY, authority_iface_init)
                         G_IMPLEMENT_INTERFACE (_POLKIT_TYPE_AUTHORITY_MANAGER, authority_manager_iface_init)
                         );

static void
server_init (Server *local_server)
{
}

static void
server_finalize (GObject *object)
{
  Server *server;

  server = SERVER (object);

  g_free (server->well_known_name);

  /* TODO: release well_known_name if not NULL */

  g_signal_handler_disconnect (server->bus, server->name_owner_changed_id);

  g_object_unref (server->bus_proxy);

  g_object_unref (server->system_bus);

  g_signal_handler_disconnect (server->authority, server->authority_changed_id);

}

static void
server_class_init (ServerClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = server_finalize;
}

static void
name_owner_changed (EggDBusBus *instance,
                    gchar      *name,
                    gchar      *old_owner,
                    gchar      *new_owner,
                    Server     *server)
{
  polkit_backend_authority_system_bus_name_owner_changed (server->authority, name, old_owner, new_owner);
}

static void
authority_changed (PolkitBackendAuthority *authority,
                   Server                 *server)
{
  _polkit_authority_emit_signal_changed (_POLKIT_AUTHORITY (server), NULL);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_enumerate_actions (_PolkitAuthority        *instance,
                                    const gchar             *locale,
                                    EggDBusMethodInvocation *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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
authority_manager_handle_enumerate_users (_PolkitAuthorityManager *instance,
                                          EggDBusMethodInvocation *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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

  _polkit_authority_manager_handle_enumerate_users_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                           array);

  g_object_unref (array);

  g_list_foreach (users, (GFunc) g_object_unref, NULL);
  g_list_free (users);

  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_enumerate_groups (_PolkitAuthorityManager *instance,
                                           EggDBusMethodInvocation *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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

  _polkit_authority_manager_handle_enumerate_groups_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
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
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitSubject *subject;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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
authority_manager_handle_enumerate_authorizations (_PolkitAuthorityManager        *instance,
                                                   _PolkitIdentity                *real_identity,
                                                   EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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

  _polkit_authority_manager_handle_enumerate_authorizations_finish (_polkit_backend_pending_call_get_method_invocation (pending_call),
                                                                    array);

  g_object_unref (array);

  g_list_foreach (authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (authorizations);

  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_add_authorization (_PolkitAuthorityManager        *instance,
                                            _PolkitIdentity                *real_identity,
                                            _PolkitAuthorization           *real_authorization,
                                            EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;
  PolkitAuthorization *authorization;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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
  _polkit_authority_manager_handle_add_authorization_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_remove_authorization (_PolkitAuthorityManager        *instance,
                                               _PolkitIdentity                *real_identity,
                                               _PolkitAuthorization           *real_authorization,
                                               EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;
  PolkitAuthorization *authorization;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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
  _polkit_authority_manager_handle_remove_authorization_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_register_authentication_agent (_PolkitAuthority               *instance,
                                                const gchar                    *object_path,
                                                EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

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
authority_handle_authentication_agent_response (_PolkitAuthority               *instance,
                                                const gchar                    *cookie,
                                                _PolkitIdentity                *real_identity,
                                                EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitBackendPendingCall *pending_call;
  PolkitIdentity *identity;

  pending_call = _polkit_backend_pending_call_new (method_invocation);

  identity = polkit_identity_new_for_real (real_identity);

  g_object_set_data_full (G_OBJECT (pending_call), "identity", identity, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_authentication_agent_response (server->authority,
                                                          cookie,
                                                          identity,
                                                          pending_call);
}

void
polkit_backend_authority_authentication_agent_response_finish (PolkitBackendPendingCall  *pending_call)
{
  _polkit_authority_handle_authentication_agent_response_finish (_polkit_backend_pending_call_get_method_invocation (pending_call));
  g_object_unref (pending_call);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_iface_init (_PolkitAuthorityIface *authority_iface)
{
  authority_iface->handle_enumerate_actions               = authority_handle_enumerate_actions;
  authority_iface->handle_check_authorization             = authority_handle_check_authorization;
  authority_iface->handle_register_authentication_agent   = authority_handle_register_authentication_agent;
  authority_iface->handle_unregister_authentication_agent = authority_handle_unregister_authentication_agent;
  authority_iface->handle_authentication_agent_response   = authority_handle_authentication_agent_response;
}

static void
authority_manager_iface_init (_PolkitAuthorityManagerIface *authority_manager_iface)
{
  authority_manager_iface->handle_enumerate_users                 = authority_manager_handle_enumerate_users;
  authority_manager_iface->handle_enumerate_groups                = authority_manager_handle_enumerate_groups;
  authority_manager_iface->handle_enumerate_authorizations        = authority_manager_handle_enumerate_authorizations;
  authority_manager_iface->handle_add_authorization               = authority_manager_handle_add_authorization;
  authority_manager_iface->handle_remove_authorization            = authority_manager_handle_remove_authorization;
}

static void
authority_died (gpointer user_data,
                GObject *where_the_object_was)
{
  Server *server = SERVER (user_data);

  g_object_unref (server);
}

/**
 * polkit_backend_register_authority:
 * @authority: A #PolkitBackendAuthority.
 * @well_known_name: Well-known name to claim on the system bus or %NULL to not claim a well-known name.
 * @object_path: Object path of the authority.
 * @error: Return location for error.
 *
 * Registers @authority on the system message bus.
 *
 * Returns: %TRUE if @authority was registered, %FALSE if @error is set.
 **/
gboolean
polkit_backend_register_authority (PolkitBackendAuthority   *authority,
                                   const gchar              *well_known_name,
                                   const gchar              *object_path,
                                   GError                  **error)
{
  Server *server;
  EggDBusRequestNameReply rn_ret;

  server = SERVER (g_object_new (TYPE_SERVER, NULL));

  server->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  server->well_known_name = g_strdup (well_known_name);

  if (well_known_name != NULL)
    {
      if (!egg_dbus_bus_request_name_sync (egg_dbus_connection_get_bus (server->system_bus),
                                           EGG_DBUS_CALL_FLAGS_NONE,
                                           well_known_name,
                                           EGG_DBUS_REQUEST_NAME_FLAGS_NONE,
                                           &rn_ret,
                                           NULL,
                                           error))
        {
          goto error;
        }

      if (rn_ret != EGG_DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Could not become primary name owner for %s",
                       well_known_name);
          goto error;
        }
    }

  server->authority = authority;

  /* TODO: it's a bit wasteful listening to all name-owner-changed signals... needs to be optimized */
  server->bus_proxy = egg_dbus_connection_get_object_proxy (server->system_bus,
                                                            "org.freedesktop.DBus",
                                                            "/org/freedesktop/DBus");

  server->bus = EGG_DBUS_QUERY_INTERFACE_BUS (server->bus_proxy);

  server->name_owner_changed_id = g_signal_connect (server->bus,
                                                    "name-owner-changed",
                                                    (GCallback) name_owner_changed,
                                                    server);

  server->authority_changed_id = g_signal_connect (server->authority,
                                                   "changed",
                                                   (GCallback) authority_changed,
                                                   server);

  egg_dbus_connection_register_interface (server->system_bus,
                                          object_path,
                                          _POLKIT_TYPE_AUTHORITY,
                                          G_OBJECT (server),
                                          _POLKIT_TYPE_AUTHORITY_MANAGER,
                                          G_OBJECT (server),
                                          G_TYPE_INVALID);

  /* take a weak ref and kill server when listener dies */
  g_object_weak_ref (G_OBJECT (server->authority), authority_died, server);

  return TRUE;

 error:
  g_object_unref (server);
  return FALSE;
}

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

#include <polkit/polkitprivate.h>
#include "_polkitagentbindings.h"

#include "polkitagentlistener.h"

/**
 * SECTION:polkitagentlistener
 * @title: PolkitAgentListener
 * @short_description: Authentication Agent Listener
 *
 * The #PolkitAgentListener is an abstract base class used for implementing authentication agents.
 */

/* private class for exporting an interface D-Bus */

#define TYPE_SERVER         (server_get_type ())
#define SERVER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), TYPE_SERVER, Server))
#define SERVER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_AGENT_TYPE_LISTENER, ServerClass))
#define SERVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), TYPE_SERVER, ServerClass))
#define IS_SERVER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), TYPE_SERVER))
#define IS_SERVER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), TYPE_SERVER))

typedef struct _Server Server;
typedef struct _ServerClass ServerClass;

struct _Server
{
  GObject parent_instance;

  EggDBusConnection *system_bus;

  EggDBusObjectProxy *authority_proxy;

  PolkitAuthority *authority;

  gboolean is_registered;

  PolkitAgentListener *listener;

  gchar *session_id;
  gchar *object_path;

  GHashTable *cookie_to_pending_auth;

};

struct _ServerClass
{
  GObjectClass parent_class;

};

static GType server_get_type (void) G_GNUC_CONST;

static void authentication_agent_iface_init (_PolkitAgentAuthenticationAgentIface *agent_iface);

G_DEFINE_TYPE_WITH_CODE (Server, server, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (_POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT,
                                                authentication_agent_iface_init)
                         );

static gboolean
server_register (Server   *server,
                 GError  **error)
{
  GError *local_error;
  gboolean ret;

  ret = FALSE;

  local_error = NULL;
  /* TODO: also pass server->session_id */
  if (!polkit_authority_register_authentication_agent_sync (server->authority,
                                                            server->object_path,
                                                            NULL,
                                                            &local_error))
    {
      g_warning ("Unable to register authentication agent: %s", local_error->message);
      g_propagate_error (error, local_error);
    }
  else
    {
      server->is_registered = TRUE;
      ret = TRUE;
    }

  return ret;
}

static void
name_owner_notify (EggDBusObjectProxy *object_proxy,
                   GParamSpec *pspec,
                   gpointer user_data)
{
  Server *server = SERVER (user_data);
  gchar *owner;

  owner = egg_dbus_object_proxy_get_name_owner (server->authority_proxy);

  if (owner == NULL)
    {
      g_printerr ("PolicyKit daemon disconnected from the bus.\n");

      if (server->is_registered)
        g_printerr ("We are no longer a registered authentication agent.\n");

      server->is_registered = FALSE;
    }
  else
    {
      /* only register if there is a name owner */
      if (!server->is_registered)
        {
          GError *error;

          g_printerr ("PolicyKit daemon reconnected to bus.\n");
          g_printerr ("Attempting to re-register as an authentication agent.\n");

          error = NULL;
          if (server_register (server, &error))
            {
              g_printerr ("We are now a registered authentication agent.\n");
            }
          else
            {
              g_printerr ("Failed to register as an authentication agent: %s\n", error->message);
              g_error_free (error);
            }
        }
    }

  g_free (owner);
}

static void
server_init (Server *server)
{
  server->cookie_to_pending_auth = g_hash_table_new (g_str_hash, g_str_equal);

  server->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  server->authority = polkit_authority_get ();

  /* the only use of this proxy is to re-register with the polkit daemon
   * if it jumps off the bus and comes back (which is useful for debugging)
   */
  server->authority_proxy = egg_dbus_connection_get_object_proxy (server->system_bus,
                                                                  "org.freedesktop.PolicyKit1",
                                                                  "/org/freedesktop/PolicyKit1/Authority");

  g_signal_connect (server->authority_proxy,
                    "notify::name-owner",
                    G_CALLBACK (name_owner_notify),
                    server);
}

static void
server_finalize (GObject *object)
{
  Server *server = SERVER (object);

  if (server->is_registered)
    {
      GError *error;

      error = NULL;
      if (!polkit_authority_unregister_authentication_agent_sync (server->authority,
                                                                  server->object_path,
                                                                  NULL,
                                                                  &error))
        {
          g_warning ("Error unregistering authentication agent: %s", error->message);
          g_error_free (error);
        }
    }

  g_free (server->session_id);
  g_free (server->object_path);

  g_object_unref (server->authority);

  g_object_unref (server->authority_proxy);

  g_object_unref (server->system_bus);

  g_hash_table_unref (server->cookie_to_pending_auth);

  if (G_OBJECT_CLASS (server_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (server_parent_class)->finalize (object);
}

static void
server_class_init (ServerClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = server_finalize;
}

static void
listener_died (gpointer user_data,
               GObject *where_the_object_was)
{
  Server *server = SERVER (user_data);

  g_object_unref (server);
}

void
polkit_agent_export_listener (PolkitAgentListener  *listener,
                              const gchar          *session_id,
                              const gchar          *object_path)
{
  Server *server;
  GError *error;

  server = SERVER (g_object_new (TYPE_SERVER, NULL));
  server->session_id = g_strdup (session_id);
  server->object_path = g_strdup (object_path);
  server->listener = listener;

  /* take a weak ref and kill server when listener dies */
  g_object_weak_ref (G_OBJECT (server->listener), listener_died, server);

  egg_dbus_connection_register_interface (server->system_bus,
                                          server->object_path,
                                          _POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT,
                                          G_OBJECT (server),
                                          G_TYPE_INVALID);

  error = NULL;
  if (!server_register (server, &error))
    {
      g_printerr ("Failed to register as an authentication agent: %s\n", error->message);
      g_printerr ("Will attempt to register when the PolicyKit daemon is back up\n");
      g_error_free (error);
    }
}

typedef struct
{
  Server *server;
  gchar *cookie;
  EggDBusMethodInvocation *method_invocation;
  GCancellable *cancellable;
} AuthData;

static AuthData *
auth_data_new (Server                  *server,
               const gchar             *cookie,
               EggDBusMethodInvocation *method_invocation,
               GCancellable            *cancellable)
{
  AuthData *data;

  data = g_new0 (AuthData, 1);
  data->server = g_object_ref (server);
  data->cookie = g_strdup (cookie);
  data->method_invocation = g_object_ref (method_invocation);
  data->cancellable = g_object_ref (cancellable);

  return data;
}

static void
auth_data_free (AuthData *data)
{
  g_object_unref (data->server);
  g_free (data->cookie);
  g_object_unref (data->method_invocation);
  g_object_unref (data->cancellable);
  g_free (data);
}

static void
auth_cb (GObject      *source_object,
         GAsyncResult *res,
         gpointer      user_data)
{
  AuthData *data = user_data;
  GError *error;

  error = NULL;
  if (!polkit_agent_listener_initiate_authentication_finish (POLKIT_AGENT_LISTENER (source_object),
                                                             res,
                                                             &error))
    {
      egg_dbus_method_invocation_return_gerror (data->method_invocation, error);
      g_error_free (error);
    }
  else
    {
      _polkit_agent_authentication_agent_handle_begin_authentication_finish (data->method_invocation);
    }

  g_hash_table_remove (data->server->cookie_to_pending_auth, data->cookie);

  auth_data_free (data);
}

static void
handle_begin_authentication (_PolkitAgentAuthenticationAgent *instance,
                             const gchar                     *action_id,
                             const gchar                     *cookie,
                             EggDBusArraySeq                 *identities,
                             EggDBusMethodInvocation         *method_invocation)
{
  Server *server = SERVER (instance);
  AuthData *data;
  GList *list;
  guint n;
  GCancellable *cancellable;

  list = NULL;
  for (n = 0; n < identities->size; n++)
    {
      _PolkitIdentity *real_identity = _POLKIT_IDENTITY (identities->data.v_ptr[n]);

      list = g_list_prepend (list, polkit_identity_new_for_real (real_identity));
    }

  list = g_list_reverse (list);

  cancellable = g_cancellable_new ();
  data = auth_data_new (server,
                        cookie,
                        method_invocation,
                        cancellable);
  g_object_unref (cancellable);

  g_hash_table_insert (server->cookie_to_pending_auth, (gpointer) cookie, data);

  polkit_agent_listener_initiate_authentication (server->listener,
                                                 action_id,
                                                 cookie,
                                                 list,
                                                 data->cancellable,
                                                 auth_cb,
                                                 data);

  g_list_free (list);
}

static void
handle_cancel_authentication (_PolkitAgentAuthenticationAgent *instance,
                              const gchar                     *cookie,
                              EggDBusMethodInvocation         *method_invocation)
{
  Server *server = SERVER (instance);
  AuthData *data;

  data = g_hash_table_lookup (server->cookie_to_pending_auth, cookie);
  if (data == NULL)
    {
      egg_dbus_method_invocation_return_error (method_invocation,
                                               POLKIT_ERROR,
                                               POLKIT_ERROR_FAILED,
                                               "No pending authentication request for cookie '%s'",
                                               cookie);
    }
  else
    {
      g_cancellable_cancel (data->cancellable);
      _polkit_agent_authentication_agent_handle_cancel_authentication_finish (method_invocation);
    }
}

static void
authentication_agent_iface_init (_PolkitAgentAuthenticationAgentIface *agent_iface)
{
  agent_iface->handle_begin_authentication = handle_begin_authentication;
  agent_iface->handle_cancel_authentication = handle_cancel_authentication;
}

/* ---------------------------------------------------------------------------------------------------- */

G_DEFINE_ABSTRACT_TYPE (PolkitAgentListener, polkit_agent_listener, G_TYPE_OBJECT);

static void
polkit_agent_listener_init (PolkitAgentListener *listener)
{
}

static void
polkit_agent_listener_class_init (PolkitAgentListenerClass *klass)
{
}

void
polkit_agent_listener_initiate_authentication (PolkitAgentListener  *listener,
                                               const gchar          *action_id,
                                               const gchar          *cookie,
                                               GList                *identities,
                                               GCancellable         *cancellable,
                                               GAsyncReadyCallback   callback,
                                               gpointer              user_data)
{
  POLKIT_AGENT_LISTENER_GET_CLASS (listener)->initiate_authentication (listener,
                                                                       action_id,
                                                                       cookie,
                                                                       identities,
                                                                       cancellable,
                                                                       callback,
                                                                       user_data);
}

gboolean
polkit_agent_listener_initiate_authentication_finish (PolkitAgentListener  *listener,
                                                      GAsyncResult         *res,
                                                      GError              **error)
{
  return POLKIT_AGENT_LISTENER_GET_CLASS (listener)->initiate_authentication_finish (listener,
                                                                                     res,
                                                                                     error);
}


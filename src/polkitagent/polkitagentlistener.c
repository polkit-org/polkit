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

#include "polkitagentlistener.h"

/**
 * SECTION:polkitagentlistener
 * @title: PolkitAgentListener
 * @short_description: Abstract base class for Authentication Agents
 * @stability: Unstable
 *
 * #PolkitAgentListener is an abstract base class used for implementing authentication
 * agents. To implement an authentication agent, simply subclass #PolkitAgentListener and
 * implement the @initiate_authentication and @initiate_authentication_finish VFuncs.
 *
 * Typically authentication agents use #PolkitAgentSession to authenticate users (via
 * passwords) and communicate back the authentication result to the PolicyKit daemon.
 * This is however not requirement. Depending on the system an authentication agent
 * may use other means (such as a Yes/No dialog) to obtain sufficient evidence that
 * the user is one of the requested identities.
 *
 * To register a #PolkitAgentListener with the PolicyKit daemon, use polkit_agent_register_listener().
 */

typedef struct
{
  GObject parent_instance;

  GDBusConnection *system_bus;
  guint auth_agent_registration_id;

  PolkitAuthority *authority;
  gulong notify_owner_handler_id;

  gboolean is_registered;

  PolkitAgentListener *listener;

  PolkitSubject *subject;
  gchar *object_path;

  GHashTable *cookie_to_pending_auth;
} Server;

static void
server_free (Server *server)
{
  if (server->is_registered)
    {
      GError *error;
      error = NULL;
      if (!polkit_authority_unregister_authentication_agent_sync (server->authority,
                                                                  server->subject,
                                                                  server->object_path,
                                                                  NULL,
                                                                  &error))
        {
          g_warning ("Error unregistering authentication agent: %s", error->message);
          g_error_free (error);
        }
    }

  if (server->auth_agent_registration_id > 0)
    g_dbus_connection_unregister_object (server->system_bus, server->auth_agent_registration_id);

  if (server->notify_owner_handler_id > 0)
    g_signal_handler_disconnect (server->authority, server->notify_owner_handler_id);

  if (server->authority != NULL)
    g_object_unref (server->authority);

  if (server->system_bus != NULL)
    g_object_unref (server->system_bus);

  if (server->cookie_to_pending_auth != NULL)
    g_hash_table_unref (server->cookie_to_pending_auth);

  if (server->subject != NULL)
    g_object_unref (server->subject);

  g_free (server->object_path);
}

static gboolean
server_register (Server   *server,
                 GError  **error)
{
  GError *local_error;
  gboolean ret;

  ret = FALSE;

  local_error = NULL;
  if (!polkit_authority_register_authentication_agent_sync (server->authority,
                                                            server->subject,
                                                            g_getenv ("LANG"),
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
on_notify_authority_owner (GObject    *object,
                           GParamSpec *pspec,
                           gpointer    user_data)
{
  Server *server = user_data;
  gchar *owner;

  owner = polkit_authority_get_owner (server->authority);
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

static gboolean
server_init_sync (Server        *server,
                  GCancellable  *cancellable,
                  GError       **error)
{
  gboolean ret;

  ret = FALSE;

  server->system_bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, cancellable, error);
  if (server->system_bus == NULL)
    goto out;

  server->authority = polkit_authority_get ();
  if (server->authority == NULL)
    goto out;

  /* the only use of this proxy is to re-register with the polkit daemon
   * if it jumps off the bus and comes back (which is useful for debugging)
   */
  server->notify_owner_handler_id = g_signal_connect (server->authority,
                                                      "notify::owner",
                                                      G_CALLBACK (on_notify_authority_owner),
                                                      server);

  ret = TRUE;

 out:
  return ret;
}

static Server *
server_new (PolkitSubject  *subject,
            const gchar    *object_path,
            GCancellable   *cancellable,
            GError        **error)
{
  Server *server;

  server = g_new0 (Server, 1);
  server->subject = g_object_ref (subject);
  server->object_path = object_path != NULL ? g_strdup (object_path) :
                                              g_strdup ("/org/freedesktop/PolicyKit1/AuthenticationAgent");
  server->cookie_to_pending_auth = g_hash_table_new (g_str_hash, g_str_equal);

  if (!server_init_sync (server, cancellable, error))
    {
      server_free (server);
      goto out;
    }

 out:
  return server;
}

static void
listener_died (gpointer user_data,
               GObject *where_the_object_was)
{
  Server *server = user_data;

  server_free (server);
}

static void auth_agent_handle_begin_authentication (Server                 *server,
                                                    GVariant               *parameters,
                                                    GDBusMethodInvocation  *invocation);

static void auth_agent_handle_cancel_authentication (Server                 *server,
                                                     GVariant               *parameters,
                                                     GDBusMethodInvocation  *invocation);

static void
auth_agent_handle_method_call (GDBusConnection        *connection,
                               const gchar            *sender,
                               const gchar            *object_path,
                               const gchar            *interface_name,
                               const gchar            *method_name,
                               GVariant               *parameters,
                               GDBusMethodInvocation  *invocation,
                               gpointer                user_data)
{
  Server *server = user_data;

  /* The shipped D-Bus policy also ensures that only uid 0 can invoke
   * methods on our interface. So no need to check the caller.
   */

  if (g_strcmp0 (method_name, "BeginAuthentication") == 0)
    auth_agent_handle_begin_authentication (server, parameters, invocation);
  else if (g_strcmp0 (method_name, "CancelAuthentication") == 0)
    auth_agent_handle_cancel_authentication (server, parameters, invocation);
  else
    g_assert_not_reached ();
}

static const gchar *auth_agent_introspection_data =
  "<node>"
  "  <interface name='org.freedesktop.PolicyKit1.AuthenticationAgent'>"
  "    <method name='BeginAuthentication'>"
  "      <arg type='s' name='action_id' direction='in'/>"
  "      <arg type='s' name='message' direction='in'/>"
  "      <arg type='s' name='icon_name' direction='in'/>"
  "      <arg type='a{ss}' name='details' direction='in'/>"
  "      <arg type='s' name='cookie' direction='in'/>"
  "      <arg type='a(sa{sv})' name='identities' direction='in'/>"
  "    </method>"
  "    <method name='CancelAuthentication'>"
  "      <arg type='s' name='cookie' direction='in'/>"
  "    </method>"
  "  </interface>"
  "</node>";

static const GDBusInterfaceVTable auth_agent_vtable =
{
  auth_agent_handle_method_call,
  NULL, /* _handle_get_property */
  NULL  /* _handle_set_property */
};

/**
 * polkit_agent_register_listener:
 * @listener: An instance of a class that is derived from #PolkitAgentListener.
 * @subject: The subject to become an authentication agent for, typically a #PolkitUnixSession object.
 * @object_path: The D-Bus object path to use for the authentication agent or %NULL for the default object path.
 * @error: Return location for error.
 *
 * Registers @listener with the PolicyKit daemon as an authentication agent for @subject. This
 * is implemented by registering a D-Bus object at @object_path on the unique name assigned by the
 * system message bus.
 *
 * Whenever the PolicyKit daemon needs to authenticate a processes that is related @subject, the methods
 * polkit_agent_listener_initiate_authentication() and polkit_agent_listener_initiate_authentication_finish()
 * will be invoked on @listener.
 *
 * Note that registration of an authentication agent can fail; for example another authentication agent may
 * already be registered.
 *
 * To unregister @listener, simply free it with g_object_unref().
 *
 * Returns: %TRUE if @listener has been registered, %FALSE if @error is set.
 **/
gboolean
polkit_agent_register_listener (PolkitAgentListener  *listener,
                                PolkitSubject        *subject,
                                const gchar          *object_path,
                                GError              **error)
{
  Server *server;
  gboolean ret;
  GDBusNodeInfo *node_info;

  ret = FALSE;

  server = server_new (subject, object_path, NULL, error);
  if (server == NULL)
    goto out;

  node_info = g_dbus_node_info_new_for_xml (auth_agent_introspection_data, error);
  if (node_info == NULL)
    goto out;

  server->listener = listener;
  server->auth_agent_registration_id = g_dbus_connection_register_object (server->system_bus,
                                                                          server->object_path,
                                                                          g_dbus_node_info_lookup_interface (node_info, "org.freedesktop.PolicyKit1.AuthenticationAgent"),
                                                                          &auth_agent_vtable,
                                                                          server,
                                                                          NULL, /* user_data GDestroyNotify */
                                                                          error);
  g_dbus_node_info_unref (node_info);

  if (server->auth_agent_registration_id == 0)
    {
      server_free (server);
      goto out;
    }

  if (!server_register (server, error))
    {
      server_free (server);
      goto out;
    }

  /* take a weak ref and kill server when listener dies */
  g_object_weak_ref (G_OBJECT (server->listener), listener_died, server);

  ret = TRUE;

 out:
  return ret;
}

typedef struct
{
  Server *server;
  gchar *cookie;
  GDBusMethodInvocation *invocation;
  GCancellable *cancellable;
} AuthData;

static void
auth_data_free (AuthData *data)
{
  g_free (data->cookie);
  g_object_unref (data->invocation);
  g_object_unref (data->cancellable);
  g_free (data);
}

/* ---------------------------------------------------------------------------------------------------- */

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
      g_dbus_method_invocation_return_gerror (data->invocation, error);
      g_error_free (error);
    }
  else
    {
      g_dbus_method_invocation_return_value (data->invocation, NULL);
    }

  g_hash_table_remove (data->server->cookie_to_pending_auth, data->cookie);

  auth_data_free (data);
}

static void
auth_agent_handle_begin_authentication (Server                 *server,
                                        GVariant               *parameters,
                                        GDBusMethodInvocation  *invocation)
{
  const gchar *action_id;
  const gchar *message;
  const gchar *icon_name;
  GVariant    *details_gvariant;
  const gchar *cookie;
  GVariant    *identities_gvariant;
  GList *identities;
  PolkitDetails *details;
  GVariantIter iter;
  GVariant *child;
  guint n;
  AuthData *data;

  identities = NULL;
  details = NULL;

  g_variant_get (parameters,
                 "(&s&s&s@a{ss}&s@a(sa{sv}))",
                 &action_id,
                 &message,
                 &icon_name,
                 &details_gvariant,
                 &cookie,
                 &identities_gvariant);

  details = polkit_details_new_for_gvariant (details_gvariant);

  g_variant_iter_init (&iter, identities_gvariant);
  n = 0;
  while ((child = g_variant_iter_next_value (&iter)) != NULL)
    {
      PolkitIdentity *identity;
      GError *error;
      error = NULL;
      identity = polkit_identity_new_for_gvariant (child, &error);
      g_variant_unref (child);

      if (identity == NULL)
        {
          g_prefix_error (&error, "Error extracting identity %d: ", n);
          g_dbus_method_invocation_return_gerror (invocation, error);
          g_error_free (error);
          goto out;
        }
      n++;

      identities = g_list_prepend (identities, identity);
    }
  identities = g_list_reverse (identities);

  data = g_new0 (AuthData, 1);
  data->server = server;
  data->cookie = g_strdup (cookie);
  data->invocation = g_object_ref (invocation);
  data->cancellable = g_cancellable_new ();

  g_hash_table_insert (server->cookie_to_pending_auth, (gpointer) cookie, data);

  polkit_agent_listener_initiate_authentication (server->listener,
                                                 action_id,
                                                 message,
                                                 icon_name,
                                                 details,
                                                 cookie,
                                                 identities,
                                                 data->cancellable,
                                                 auth_cb,
                                                 data);

 out:
  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);
  g_object_unref (details);
  g_variant_unref (details_gvariant);
  g_variant_unref (identities_gvariant);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
auth_agent_handle_cancel_authentication (Server                 *server,
                                         GVariant               *parameters,
                                         GDBusMethodInvocation  *invocation)
{
  AuthData *data;
  const gchar *cookie;

  g_variant_get (parameters,
                 "(&s)",
                 &cookie);

  data = g_hash_table_lookup (server->cookie_to_pending_auth, cookie);
  if (data == NULL)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             POLKIT_ERROR,
                                             POLKIT_ERROR_FAILED,
                                             "No pending authentication request for cookie '%s'",
                                             cookie);
    }
  else
    {
      g_cancellable_cancel (data->cancellable);
      g_dbus_method_invocation_return_value (invocation, NULL);
    }
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

/**
 * polkit_agent_listener_initiate_authentication:
 * @listener: A #PolkitAgentListener.
 * @action_id: The action to authenticate for.
 * @message: The message to present to the user.
 * @icon_name: A themed icon name representing the action or %NULL.
 * @details: Details describing the action.
 * @cookie: The cookie for the authentication request.
 * @identities: A list of #PolkitIdentity objects that the user can choose to authenticate as.
 * @cancellable: A #GCancellable.
 * @callback: Function to call when the user is done authenticating.
 * @user_data: Data to pass to @callback.
 *
 * Called on a registered authentication agent (see polkit_agent_register_listener()) when
 * the user owning the session needs to prove he is one of the identities listed in @identities.
 *
 * When the user is done authenticating (for example by dismissing an authentication dialog
 * or by successfully entering a password or otherwise proving the user is one of the
 * identities in @identities), @callback will be invoked. The caller then calls
 * polkit_agent_listener_initiate_authentication_finish() to get the result.
 *
 * #PolkitAgentListener derived subclasses imlementing this method MUST not
 * ignore @cancellable; callers of this function can and will use it.
 **/
void
polkit_agent_listener_initiate_authentication (PolkitAgentListener  *listener,
                                               const gchar          *action_id,
                                               const gchar          *message,
                                               const gchar          *icon_name,
                                               PolkitDetails        *details,
                                               const gchar          *cookie,
                                               GList                *identities,
                                               GCancellable         *cancellable,
                                               GAsyncReadyCallback   callback,
                                               gpointer              user_data)
{
  POLKIT_AGENT_LISTENER_GET_CLASS (listener)->initiate_authentication (listener,
                                                                       action_id,
                                                                       message,
                                                                       icon_name,
                                                                       details,
                                                                       cookie,
                                                                       identities,
                                                                       cancellable,
                                                                       callback,
                                                                       user_data);
}

/**
 * polkit_agent_listener_initiate_authentication_finish:
 * @listener: A #PolkitAgentListener.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback function passed to polkit_agent_listener_initiate_authentication().
 * @error: Return location for error.
 *
 * Finishes an authentication request from the PolicyKit daemon, see
 * polkit_agent_listener_initiate_authentication() for details.
 *
 * Returns: %TRUE if @error is set.
 **/
gboolean
polkit_agent_listener_initiate_authentication_finish (PolkitAgentListener  *listener,
                                                      GAsyncResult         *res,
                                                      GError              **error)
{
  return POLKIT_AGENT_LISTENER_GET_CLASS (listener)->initiate_authentication_finish (listener,
                                                                                     res,
                                                                                     error);
}


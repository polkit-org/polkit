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
#include <syslog.h>
#include <stdarg.h>

#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>

#include "polkitbackendauthority.h"
#include "polkitbackendjsauthority.h"

#include "polkitbackendprivate.h"

/**
 * SECTION:polkitbackendauthority
 * @title: PolkitBackendAuthority
 * @short_description: Abstract base class for authority backends
 * @stability: Unstable
 * @see_also: PolkitBackendJsAuthority
 *
 * To implement an authority backend, simply subclass #PolkitBackendAuthority
 * and implement the required VFuncs.
 */

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_ABSTRACT_TYPE (PolkitBackendAuthority, polkit_backend_authority, G_TYPE_OBJECT);

static void
polkit_backend_authority_init (PolkitBackendAuthority *authority)
{
}

static void
polkit_backend_authority_class_init (PolkitBackendAuthorityClass *klass)
{
  /**
   * PolkitBackendAuthority::changed:
   * @authority: A #PolkitBackendAuthority.
   *
   * Emitted when actions and/or authorizations change.
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_BACKEND_TYPE_AUTHORITY,
                                          G_SIGNAL_RUN_LAST,
                                          G_STRUCT_OFFSET (PolkitBackendAuthorityClass, changed),
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

/**
 * polkit_backend_authority_get_name:
 * @authority: A #PolkitBackendAuthority.
 *
 * Gets the name of the authority backend.
 *
 * Returns: The name of the backend.
 */
const gchar *
polkit_backend_authority_get_name (PolkitBackendAuthority *authority)
{
  PolkitBackendAuthorityClass *klass;
  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);
  if (klass->get_name == NULL)
    return "(not set)";
  return klass->get_name (authority);
}

/**
 * polkit_backend_authority_get_version:
 * @authority: A #PolkitBackendAuthority.
 *
 * Gets the version of the authority backend.
 *
 * Returns: The name of the backend.
 */
const gchar *
polkit_backend_authority_get_version (PolkitBackendAuthority *authority)
{
  PolkitBackendAuthorityClass *klass;
  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);
  if (klass->get_version == NULL)
    return "(not set)";
  return klass->get_version (authority);
}

/**
 * polkit_backend_authority_get_features:
 * @authority: A #PolkitBackendAuthority.
 *
 * Gets the features supported by the authority backend.
 *
 * Returns: Flags from #PolkitAuthorityFeatures.
 */
PolkitAuthorityFeatures
polkit_backend_authority_get_features (PolkitBackendAuthority *authority)
{
  PolkitBackendAuthorityClass *klass;
  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);
  if (klass->get_features == NULL)
    return POLKIT_AUTHORITY_FEATURES_NONE;
  return klass->get_features (authority);
}

/**
 * polkit_backend_authority_enumerate_actions:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @locale: The locale to retrieve descriptions for.
 * @error: Return location for error or %NULL.
 *
 * Retrieves all registered actions.
 *
 * Returns: A list of #PolkitActionDescription objects or %NULL if @error is set. The returned list
 * should be freed with g_list_free() after each element have been freed with g_object_unref().
 **/
GList *
polkit_backend_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                            PolkitSubject            *caller,
                                            const gchar              *locale,
                                            GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->enumerate_actions == NULL)
    {
      g_warning ("enumerate_actions is not implemented (it is not optional)");
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported (bug in backend)");
      return NULL;
    }
  else
    {
      return klass->enumerate_actions (authority, caller, locale, error);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_backend_authority_check_authorization:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @subject: A #PolkitSubject.
 * @action_id: The action to check for.
 * @details: Details about the action or %NULL.
 * @flags: A set of #PolkitCheckAuthorizationFlags.
 * @cancellable: A #GCancellable.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously checks if @subject is authorized to perform the action represented
 * by @action_id.
 *
 * When the operation is finished, @callback will be invoked. You can then
 * call polkit_backend_authority_check_authorization_finish() to get the result of
 * the operation.
 **/
void
polkit_backend_authority_check_authorization (PolkitBackendAuthority        *authority,
                                              PolkitSubject                 *caller,
                                              PolkitSubject                 *subject,
                                              const gchar                   *action_id,
                                              PolkitDetails                 *details,
                                              PolkitCheckAuthorizationFlags  flags,
                                              GCancellable                  *cancellable,
                                              GAsyncReadyCallback            callback,
                                              gpointer                       user_data)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->check_authorization == NULL)
    {
      GSimpleAsyncResult *simple;

      g_warning ("check_authorization is not implemented (it is not optional)");

      simple = g_simple_async_result_new_error (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                POLKIT_ERROR,
                                                POLKIT_ERROR_NOT_SUPPORTED,
                                                "Operation not supported (bug in backend)");
      g_simple_async_result_complete (simple);
      g_object_unref (simple);
    }
  else
    {
      klass->check_authorization (authority, caller, subject, action_id, details, flags, cancellable, callback, user_data);
    }
}

/**
 * polkit_backend_authority_check_authorization_finish:
 * @authority: A #PolkitBackendAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: Return location for error or %NULL.
 *
 * Finishes checking if a subject is authorized for an action.
 *
 * Returns: A #PolkitAuthorizationResult or %NULL if @error is set. Free with g_object_unref().
 **/
PolkitAuthorizationResult *
polkit_backend_authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                                     GAsyncResult            *res,
                                                     GError                 **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->check_authorization_finish == NULL)
    {
      g_warning ("check_authorization_finish is not implemented (it is not optional)");
      g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
      return NULL;
    }
  else
    {
      return klass->check_authorization_finish (authority, res, error);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_backend_authority_register_authentication_agent:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @subject: The subject the authentication agent wants to register for.
 * @locale: The locale of the authentication agent.
 * @object_path: The object path for the authentication agent.
 * @options: A #GVariant with options or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Registers an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_backend_authority_register_authentication_agent (PolkitBackendAuthority    *authority,
                                                        PolkitSubject             *caller,
                                                        PolkitSubject             *subject,
                                                        const gchar               *locale,
                                                        const gchar               *object_path,
                                                        GVariant                  *options,
                                                        GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->register_authentication_agent == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported");
      return FALSE;
    }
  else
    {
      return klass->register_authentication_agent (authority, caller, subject, locale, object_path, options, error);
    }
}

/**
 * polkit_backend_authority_unregister_authentication_agent:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @subject: The subject the agent claims to be registered at.
 * @object_path: The object path that the authentication agent is registered at.
 * @error: Return location for error or %NULL.
 *
 * Unregisters an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully unregistered, %FALSE if @error is set.
 **/
gboolean
polkit_backend_authority_unregister_authentication_agent (PolkitBackendAuthority    *authority,
                                                          PolkitSubject             *caller,
                                                          PolkitSubject             *subject,
                                                          const gchar               *object_path,
                                                          GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->unregister_authentication_agent == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported");
      return FALSE;
    }
  else
    {
      return klass->unregister_authentication_agent (authority, caller, subject, object_path, error);
    }
}

/**
 * polkit_backend_authority_authentication_agent_response:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @uid: The real UID of the registered agent, or (uid_t)-1 if unknown.
 * @cookie: The cookie passed to the authentication agent from the authority.
 * @identity: The identity that was authenticated.
 * @error: Return location for error or %NULL.
 *
 * Provide response that @identity successfully authenticated for the
 * authentication request identified by @cookie.
 *
 * Returns: %TRUE if @authority acknowledged the call, %FALSE if @error is set.
 **/
gboolean
polkit_backend_authority_authentication_agent_response (PolkitBackendAuthority    *authority,
                                                        PolkitSubject             *caller,
                                                        uid_t                      uid,
                                                        const gchar               *cookie,
                                                        PolkitIdentity            *identity,
                                                        GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->authentication_agent_response == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported");
      return FALSE;
    }
  else
    {
      return klass->authentication_agent_response (authority, caller, uid, cookie, identity, error);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_backend_authority_enumerate_temporary_authorizations:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @subject: The subject to get temporary authorizations for.
 * @error: Return location for error.
 *
 * Gets temporary authorizations for @subject.
 *
 * Returns: A list of #PolkitTemporaryAuthorization objects or %NULL if @error is set. The returned list
 * should be freed with g_list_free() after each element have been freed with g_object_unref().
 */
GList *
polkit_backend_authority_enumerate_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                             PolkitSubject            *caller,
                                                             PolkitSubject            *subject,
                                                             GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->enumerate_temporary_authorizations == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported");
      return NULL;
    }
  else
    {
      return klass->enumerate_temporary_authorizations (authority, caller, subject, error);
    }
}

/**
 * polkit_backend_authority_revoke_temporary_authorizations:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @subject: The subject to revoke temporary authorizations for.
 * @error: Return location for error.
 *
 * Revokes temporary authorizations for @subject.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if @error is set.
 **/
gboolean
polkit_backend_authority_revoke_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                          PolkitSubject            *caller,
                                                          PolkitSubject            *subject,
                                                          GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->revoke_temporary_authorizations == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported");
      return FALSE;
    }
  else
    {
      return klass->revoke_temporary_authorizations (authority, caller, subject, error);
    }
}

/**
 * polkit_backend_authority_revoke_temporary_authorization_by_id:
 * @authority: A #PolkitBackendAuthority.
 * @caller: The system bus name that initiated the query.
 * @id: The opaque identifier of the temporary authorization.
 * @error: Return location for error.
 *
 * Revokes a temporary authorizations with opaque identifier @id.
 *
 * Returns: %TRUE if the operation succeeded, %FALSE if @error is set.
 **/
gboolean
polkit_backend_authority_revoke_temporary_authorization_by_id (PolkitBackendAuthority   *authority,
                                                               PolkitSubject            *caller,
                                                               const gchar              *id,
                                                               GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  if (klass->revoke_temporary_authorization_by_id == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Operation not supported");
      return FALSE;
    }
  else
    {
      return klass->revoke_temporary_authorization_by_id (authority, caller, id, error);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  guint authority_registration_id;

  GDBusNodeInfo *introspection_info;

  PolkitBackendAuthority *authority;

  GDBusConnection *connection;

  gulong authority_changed_id;

  gchar *object_path;

  GHashTable *cancellation_id_to_check_auth_data;
} Server;

static void
server_free (Server *server)
{
  g_free (server->object_path);

  if (server->authority_registration_id > 0)
    g_dbus_connection_unregister_object (server->connection, server->authority_registration_id);

  if (server->connection != NULL)
    g_object_unref (server->connection);

  if (server->introspection_info != NULL)
    g_dbus_node_info_unref (server->introspection_info);

  if (server->authority != NULL && server->authority_changed_id > 0)
    g_signal_handler_disconnect (server->authority, server->authority_changed_id);

  if (server->cancellation_id_to_check_auth_data != NULL)
    g_hash_table_unref (server->cancellation_id_to_check_auth_data);

  g_object_unref (server->authority);

  g_free (server);
}

static void
on_authority_changed (PolkitBackendAuthority *authority,
                      gpointer                user_data)
{
  Server *server = user_data;
  GError *error;

  error = NULL;
  if (!g_dbus_connection_emit_signal (server->connection,
                                      NULL, /* destination bus name */
                                      server->object_path,
                                      "org.freedesktop.PolicyKit1.Authority",
                                      "Changed",
                                      NULL,
                                      &error))
    {
      g_warning ("Error emitting Changed() signal: %s", error->message);
      g_error_free (error);
    }
}

static const gchar *server_introspection_data =
  "<node>"
  "  <interface name='org.freedesktop.PolicyKit1.Authority'>"
  "    <method name='EnumerateActions'>"
  "      <arg type='s' name='locale' direction='in'/>"
  "      <arg type='a(ssssssuuua{ss})' name='action_descriptions' direction='out'/>"
  "    </method>"
  "    <method name='CheckAuthorization'>"
  "      <arg type='(sa{sv})' name='subject' direction='in'/>"
  "      <arg type='s' name='action_id' direction='in'/>"
  "      <arg type='a{ss}' name='details' direction='in'/>"
  "      <arg type='u' name='flags' direction='in'/>"
  "      <arg type='s' name='cancellation_id' direction='in'/>"
  "      <arg type='(bba{ss})' name='result' direction='out'/>"
  "    </method>"
  "    <method name='CancelCheckAuthorization'>"
  "      <arg type='s' name='cancellation_id' direction='in'/>"
  "    </method>"
  "    <method name='RegisterAuthenticationAgent'>"
  "      <arg type='(sa{sv})' name='subject' direction='in'/>"
  "      <arg type='s' name='locale' direction='in'/>"
  "      <arg type='s' name='object_path' direction='in'/>"
  "    </method>"
  "    <method name='RegisterAuthenticationAgentWithOptions'>"
  "      <arg type='(sa{sv})' name='subject' direction='in'/>"
  "      <arg type='s' name='locale' direction='in'/>"
  "      <arg type='s' name='object_path' direction='in'/>"
  "      <arg type='a{sv}' name='options' direction='in'/>"
  "    </method>"
  "    <method name='UnregisterAuthenticationAgent'>"
  "      <arg type='(sa{sv})' name='subject' direction='in'/>"
  "      <arg type='s' name='object_path' direction='in'/>"
  "    </method>"
  "    <method name='AuthenticationAgentResponse'>"
  "      <arg type='s' name='cookie' direction='in'/>"
  "      <arg type='(sa{sv})' name='identity' direction='in'/>"
  "    </method>"
  "    <method name='AuthenticationAgentResponse2'>"
  "      <arg type='u' name='uid' direction='in'/>"
  "      <arg type='s' name='cookie' direction='in'/>"
  "      <arg type='(sa{sv})' name='identity' direction='in'/>"
  "    </method>"
  "    <method name='EnumerateTemporaryAuthorizations'>"
  "      <arg type='(sa{sv})' name='subject' direction='in'/>"
  "      <arg type='a(ss(sa{sv})tt)' name='temporary_authorizations' direction='out'/>"
  "    </method>"
  "    <method name='RevokeTemporaryAuthorizations'>"
  "      <arg type='(sa{sv})' name='subject' direction='in'/>"
  "    </method>"
  "    <method name='RevokeTemporaryAuthorizationById'>"
  "      <arg type='s' name='id' direction='in'/>"
  "    </method>"
  "    <signal name='Changed'/>"
  "    <property type='s' name='BackendName' access='read'/>"
  "    <property type='s' name='BackendVersion' access='read'/>"
  "    <property type='u' name='BackendFeatures' access='read'/>"
  "  </interface>"
  "</node>";

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_enumerate_actions (Server                 *server,
                                 GVariant               *parameters,
                                 PolkitSubject          *caller,
                                 GDBusMethodInvocation  *invocation)
{
  GVariantBuilder builder;
  GError *error;
  GList *actions;
  GList *l;
  const gchar *locale;

  actions = NULL;

  g_variant_get (parameters, "(&s)", &locale);

  error = NULL;
  actions = polkit_backend_authority_enumerate_actions (server->authority,
                                                        caller,
                                                        locale,
                                                        &error);
  if (error != NULL)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(ssssssuuua{ss})"));
  for (l = actions; l != NULL; l = l->next)
    {
      PolkitActionDescription *ad = POLKIT_ACTION_DESCRIPTION (l->data);
      g_variant_builder_add_value (&builder,
                                   polkit_action_description_to_gvariant (ad)); /* A floating value */
    }
  g_dbus_method_invocation_return_value (invocation, g_variant_new ("(a(ssssssuuua{ss}))", &builder));

 out:
  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  GDBusMethodInvocation *invocation;
  Server *server;
  PolkitSubject *caller;
  PolkitSubject *subject;
  GCancellable *cancellable;
  gchar *cancellation_id;
} CheckAuthData;

static void
check_auth_data_free (CheckAuthData *data)
{
  if (data->invocation != NULL)
    g_object_unref (data->invocation);
  if (data->caller != NULL)
    g_object_unref (data->caller);
  if (data->subject != NULL)
    g_object_unref (data->subject);
  if (data->cancellable != NULL)
    g_object_unref (data->cancellable);
  g_free (data->cancellation_id);
  g_free (data);
}

static void
check_auth_cb (GObject      *source_object,
               GAsyncResult *res,
               gpointer      user_data)
{
  CheckAuthData *data = user_data;
  PolkitAuthorizationResult *result;
  GError *error;

  error = NULL;
  result = polkit_backend_authority_check_authorization_finish (POLKIT_BACKEND_AUTHORITY (source_object),
                                                                res,
                                                                &error);

  if (data->cancellation_id != NULL)
    g_hash_table_remove (data->server->cancellation_id_to_check_auth_data, data->cancellation_id);

  if (error != NULL)
    {
      g_dbus_method_invocation_return_gerror (data->invocation, error);
      g_error_free (error);
    }
  else
    {
      g_dbus_method_invocation_return_value (data->invocation,
                                             g_variant_new ("(@(bba{ss}))",
                                                            polkit_authorization_result_to_gvariant (result))); /* A floating value */
      g_object_unref (result);
    }

  check_auth_data_free (data);
}

static void
server_handle_check_authorization (Server                 *server,
                                   GVariant               *parameters,
                                   PolkitSubject          *caller,
                                   GDBusMethodInvocation  *invocation)
{
  GVariant *subject_gvariant;
  const gchar *action_id;
  GVariant *details_gvariant;
  guint32 flags;
  const gchar *cancellation_id;
  GError *error;
  PolkitSubject *subject;
  PolkitDetails *details;

  subject = NULL;
  details = NULL;

  g_variant_get (parameters,
                 "(@(sa{sv})&s@a{ss}u&s)",
                 &subject_gvariant,
                 &action_id,
                 &details_gvariant,
                 &flags,
                 &cancellation_id);

  error = NULL;
  subject = polkit_subject_new_for_gvariant (subject_gvariant, &error);
  if (subject == NULL)
    {
      g_prefix_error (&error, "Error getting subject: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  details = polkit_details_new_for_gvariant (details_gvariant);

  CheckAuthData *data;
  data = g_new0 (CheckAuthData, 1);

  data->server = server;
  data->caller = g_object_ref (caller);
  data->subject = g_object_ref (subject);
  data->invocation = g_object_ref (invocation);

  if (strlen (cancellation_id) > 0)
    {
      data->cancellation_id = g_strdup_printf ("%s-%s",
                                               g_dbus_method_invocation_get_sender (invocation),
                                               cancellation_id);
      if (g_hash_table_lookup (server->cancellation_id_to_check_auth_data, data->cancellation_id) != NULL)
        {
          gchar *message;
          message = g_strdup_printf ("Given cancellation_id %s is already in use for name %s",
                                     cancellation_id,
                                     g_dbus_method_invocation_get_sender (invocation));
          /* Don't want this error in our GError enum since libpolkit-gobject-1 users will never see it */
          g_dbus_method_invocation_return_dbus_error (invocation,
                                                      "org.freedesktop.PolicyKit1.Error.CancellationIdNotUnique",
                                                      message);
          g_free (message);
          check_auth_data_free (data);
          goto out;
        }

      data->cancellable = g_cancellable_new ();
      g_hash_table_insert (server->cancellation_id_to_check_auth_data,
                           data->cancellation_id,
                           data);
    }

  polkit_backend_authority_check_authorization (server->authority,
                                                caller,
                                                subject,
                                                action_id,
                                                details,
                                                flags,
                                                data->cancellable,
                                                check_auth_cb,
                                                data);

 out:

  g_variant_unref (subject_gvariant);
  g_variant_unref (details_gvariant);

  if (details != NULL)
    g_object_unref (details);
  if (subject != NULL)
    g_object_unref (subject);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_cancel_check_authorization (Server                 *server,
                                          GVariant               *parameters,
                                          PolkitSubject          *caller,
                                          GDBusMethodInvocation  *invocation)
{
  CheckAuthData *data;
  const gchar *cancellation_id;
  gchar *full_cancellation_id;

  g_variant_get (parameters, "(&s)", &cancellation_id);

  full_cancellation_id = g_strdup_printf ("%s-%s",
                                          g_dbus_method_invocation_get_sender (invocation),
                                          cancellation_id);

  data = g_hash_table_lookup (server->cancellation_id_to_check_auth_data, full_cancellation_id);
  if (data == NULL)
    {
      g_dbus_method_invocation_return_error (invocation,
                                             POLKIT_ERROR,
                                             POLKIT_ERROR_FAILED,
                                             "No such cancellation_id `%s' for name %s",
                                             cancellation_id,
                                             g_dbus_method_invocation_get_sender (invocation));
      goto out;
    }

  g_cancellable_cancel (data->cancellable);

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_free (full_cancellation_id);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_register_authentication_agent (Server                 *server,
                                             GVariant               *parameters,
                                             PolkitSubject          *caller,
                                             GDBusMethodInvocation  *invocation)
{
  GVariant *subject_gvariant;
  GError *error;
  PolkitSubject *subject;
  const gchar *locale;
  const gchar *object_path;

  subject = NULL;

  g_variant_get (parameters,
                 "(@(sa{sv})&s&s)",
                 &subject_gvariant,
                 &locale,
                 &object_path);

  error = NULL;
  subject = polkit_subject_new_for_gvariant (subject_gvariant, &error);
  if (subject == NULL)
    {
      g_prefix_error (&error, "Error getting subject: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_backend_authority_register_authentication_agent (server->authority,
                                                               caller,
                                                               subject,
                                                               locale,
                                                               object_path,
                                                               NULL,
                                                               &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_variant_unref (subject_gvariant);
  if (subject != NULL)
    g_object_unref (subject);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_register_authentication_agent_with_options (Server                 *server,
                                                          GVariant               *parameters,
                                                          PolkitSubject          *caller,
                                                          GDBusMethodInvocation  *invocation)
{
  GVariant *subject_gvariant;
  GError *error;
  PolkitSubject *subject;
  const gchar *locale;
  const gchar *object_path;
  GVariant *options;

  subject = NULL;

  g_variant_get (parameters,
                 "(@(sa{sv})&s&s@a{sv})",
                 &subject_gvariant,
                 &locale,
                 &object_path,
                 &options);

  error = NULL;
  subject = polkit_subject_new_for_gvariant (subject_gvariant, &error);
  if (subject == NULL)
    {
      g_prefix_error (&error, "Error getting subject: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_backend_authority_register_authentication_agent (server->authority,
                                                               caller,
                                                               subject,
                                                               locale,
                                                               object_path,
                                                               options,
                                                               &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_variant_unref (subject_gvariant);
  if (options != NULL)
      g_variant_unref (options);
  if (subject != NULL)
    g_object_unref (subject);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_unregister_authentication_agent (Server                 *server,
                                               GVariant               *parameters,
                                               PolkitSubject          *caller,
                                               GDBusMethodInvocation  *invocation)
{
  GVariant *subject_gvariant;
  GError *error;
  PolkitSubject *subject;
  const gchar *object_path;

  subject = NULL;

  g_variant_get (parameters,
                 "(@(sa{sv})&s)",
                 &subject_gvariant,
                 &object_path);

  error = NULL;
  subject = polkit_subject_new_for_gvariant (subject_gvariant, &error);
  if (subject == NULL)
    {
      g_prefix_error (&error, "Error getting subject: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_backend_authority_unregister_authentication_agent (server->authority,
                                                                 caller,
                                                                 subject,
                                                                 object_path,
                                                                 &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_variant_unref (subject_gvariant);
  if (subject != NULL)
    g_object_unref (subject);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_authentication_agent_response (Server                 *server,
                                             GVariant               *parameters,
                                             PolkitSubject          *caller,
                                             GDBusMethodInvocation  *invocation)
{
  const gchar *cookie;
  GVariant *identity_gvariant;
  PolkitIdentity *identity;
  GError *error;

  identity = NULL;

  g_variant_get (parameters,
                 "(&s@(sa{sv}))",
                 &cookie,
                 &identity_gvariant);

  error = NULL;
  identity = polkit_identity_new_for_gvariant (identity_gvariant, &error);
  if (identity == NULL)
    {
      g_prefix_error (&error, "Error getting identity: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_backend_authority_authentication_agent_response (server->authority,
                                                               caller,
                                                               (uid_t)-1,
                                                               cookie,
                                                               identity,
                                                               &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_variant_unref (identity_gvariant);
  if (identity != NULL)
    g_object_unref (identity);
}

static void
server_handle_authentication_agent_response2 (Server                 *server,
                                              GVariant               *parameters,
                                              PolkitSubject          *caller,
                                              GDBusMethodInvocation  *invocation)
{
  const gchar *cookie;
  GVariant *identity_gvariant;
  PolkitIdentity *identity;
  GError *error;
  guint32 uid;

  identity = NULL;

  g_variant_get (parameters,
                 "(u&s@(sa{sv}))",
                 &uid,
                 &cookie,
                 &identity_gvariant);

  error = NULL;
  identity = polkit_identity_new_for_gvariant (identity_gvariant, &error);
  if (identity == NULL)
    {
      g_prefix_error (&error, "Error getting identity: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_backend_authority_authentication_agent_response (server->authority,
                                                               caller,
                                                               (uid_t)uid,
                                                               cookie,
                                                               identity,
                                                               &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_variant_unref (identity_gvariant);
  if (identity != NULL)
    g_object_unref (identity);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_enumerate_temporary_authorizations (Server                 *server,
                                                  GVariant               *parameters,
                                                  PolkitSubject          *caller,
                                                  GDBusMethodInvocation  *invocation)
{
  GVariant *subject_gvariant;
  GError *error;
  PolkitSubject *subject;
  GList *authorizations;
  GList *l;
  GVariantBuilder builder;

  subject = NULL;

  g_variant_get (parameters,
                 "(@(sa{sv}))",
                 &subject_gvariant);

  error = NULL;
  subject = polkit_subject_new_for_gvariant (subject_gvariant, &error);
  if (subject == NULL)
    {
      g_prefix_error (&error, "Error getting subject: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  authorizations = polkit_backend_authority_enumerate_temporary_authorizations (server->authority,
                                                                                caller,
                                                                                subject,
                                                                                &error);
  if (error != NULL)
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a(ss(sa{sv})tt)"));
  for (l = authorizations; l != NULL; l = l->next)
    {
      PolkitTemporaryAuthorization *a = POLKIT_TEMPORARY_AUTHORIZATION (l->data);
      g_variant_builder_add_value (&builder,
                                   polkit_temporary_authorization_to_gvariant (a)); /* A floating value */
    }
  g_list_foreach (authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (authorizations);
  g_dbus_method_invocation_return_value (invocation, g_variant_new ("(a(ss(sa{sv})tt))", &builder));

 out:
  g_variant_unref (subject_gvariant);
  if (subject != NULL)
    g_object_unref (subject);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_revoke_temporary_authorizations (Server                 *server,
                                               GVariant               *parameters,
                                               PolkitSubject          *caller,
                                               GDBusMethodInvocation  *invocation)
{
  GVariant *subject_gvariant;
  GError *error;
  PolkitSubject *subject;

  subject = NULL;

  g_variant_get (parameters,
                 "(@(sa{sv}))",
                 &subject_gvariant);

  error = NULL;
  subject = polkit_subject_new_for_gvariant (subject_gvariant, &error);
  if (subject == NULL)
    {
      g_prefix_error (&error, "Error getting subject: ");
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_backend_authority_revoke_temporary_authorizations (server->authority,
                                                                 caller,
                                                                 subject,
                                                                 &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  g_variant_unref (subject_gvariant);
  if (subject != NULL)
    g_object_unref (subject);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_revoke_temporary_authorization_by_id (Server                 *server,
                                                    GVariant               *parameters,
                                                    PolkitSubject          *caller,
                                                    GDBusMethodInvocation  *invocation)
{
  GError *error;
  const gchar *id;

  g_variant_get (parameters,
                 "(&s)",
                 &id);

  error = NULL;
  if (!polkit_backend_authority_revoke_temporary_authorization_by_id (server->authority,
                                                                      caller,
                                                                      id,
                                                                      &error))
    {
      g_dbus_method_invocation_return_gerror (invocation, error);
      g_error_free (error);
      goto out;
    }

  g_dbus_method_invocation_return_value (invocation, g_variant_new ("()"));

 out:
  ;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
server_handle_method_call (GDBusConnection        *connection,
                           const gchar            *sender,
                           const gchar            *object_path,
                           const gchar            *interface_name,
                           const gchar            *method_name,
                           GVariant               *parameters,
                           GDBusMethodInvocation  *invocation,
                           gpointer                user_data)
{
  Server *server = user_data;
  PolkitSubject *caller;

  caller = polkit_system_bus_name_new (g_dbus_method_invocation_get_sender (invocation));

  if (g_strcmp0 (method_name, "EnumerateActions") == 0)
    server_handle_enumerate_actions (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "CheckAuthorization") == 0)
    server_handle_check_authorization (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "CancelCheckAuthorization") == 0)
    server_handle_cancel_check_authorization (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "RegisterAuthenticationAgent") == 0)
    server_handle_register_authentication_agent (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "RegisterAuthenticationAgentWithOptions") == 0)
    server_handle_register_authentication_agent_with_options (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "UnregisterAuthenticationAgent") == 0)
    server_handle_unregister_authentication_agent (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "AuthenticationAgentResponse") == 0)
    server_handle_authentication_agent_response (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "AuthenticationAgentResponse2") == 0)
    server_handle_authentication_agent_response2 (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "EnumerateTemporaryAuthorizations") == 0)
    server_handle_enumerate_temporary_authorizations (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "RevokeTemporaryAuthorizations") == 0)
    server_handle_revoke_temporary_authorizations (server, parameters, caller, invocation);
  else if (g_strcmp0 (method_name, "RevokeTemporaryAuthorizationById") == 0)
    server_handle_revoke_temporary_authorization_by_id (server, parameters, caller, invocation);
  else
    g_assert_not_reached ();

  g_object_unref (caller);
}

static GVariant *
server_handle_get_property (GDBusConnection  *connection,
                            const gchar      *sender,
                            const gchar      *object_path,
                            const gchar      *interface_name,
                            const gchar      *property_name,
                            GError          **error,
                            gpointer          user_data)
{
  Server *server = user_data;
  GVariant *result;

  result = NULL;

  if (g_strcmp0 (property_name, "BackendName") == 0)
    {
      result = g_variant_new_string (polkit_backend_authority_get_name (server->authority));
    }
  else if (g_strcmp0 (property_name, "BackendVersion") == 0)
    {
      result = g_variant_new_string (polkit_backend_authority_get_version (server->authority));
    }
  else if (g_strcmp0 (property_name, "BackendFeatures") == 0)
    {
      result = g_variant_new_uint32 (polkit_backend_authority_get_features (server->authority));
    }
  else
    g_assert_not_reached ();

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static const GDBusInterfaceVTable server_vtable =
{
  server_handle_method_call,
  server_handle_get_property,
  NULL, /* server_handle_set_property */
};

/**
 * polkit_backend_authority_unregister:
 * @registration_id: A #gpointer obtained from polkit_backend_authority_register().
 *
 * Unregisters a #PolkitBackendAuthority registered with polkit_backend_authority_register().
 */
void
polkit_backend_authority_unregister (gpointer registration_id)
{
  Server *server = registration_id;
  server_free (server);
}

/**
 * polkit_backend_authority_register:
 * @connection: The #GDBusConnection to register the authority on.
 * @authority: A #PolkitBackendAuthority.
 * @object_path: Object path of the authority.
 * @error: Return location for error.
 *
 * Registers @authority on a #GDBusConnection.
 *
 * Returns: A #gpointer that can be used with polkit_backend_authority_unregister() or %NULL if @error is set.
 */
gpointer
polkit_backend_authority_register (PolkitBackendAuthority   *authority,
                                   GDBusConnection          *connection,
                                   const gchar              *object_path,
                                   GError                  **error)
{
  Server *server;

  server = g_new0 (Server, 1);

  server->cancellation_id_to_check_auth_data = g_hash_table_new (g_str_hash, g_str_equal);

  server->connection = g_object_ref (connection);
  server->object_path = g_strdup (object_path);

  server->introspection_info = g_dbus_node_info_new_for_xml (server_introspection_data, error);
  if (server->introspection_info == NULL)
      goto error;

  server->authority_registration_id = g_dbus_connection_register_object (server->connection,
                                                                         object_path,
                                                                         g_dbus_node_info_lookup_interface (server->introspection_info, "org.freedesktop.PolicyKit1.Authority"),
                                                                         &server_vtable,
                                                                         server,
                                                                         NULL,
                                                                         error);
  if (server->authority_registration_id == 0)
    {
      goto error;
    }

  server->authority = g_object_ref (authority);

  server->authority_changed_id = g_signal_connect (server->authority,
                                                   "changed",
                                                   G_CALLBACK (on_authority_changed),
                                                   server);

  return server;

 error:
  server_free (server);
  return NULL;
}


/**
 * polkit_backend_authority_get:
 *
 * Gets the #PolkitBackendAuthority to use.
 *
 * Returns: A #PolkitBackendAuthority. Free with g_object_unref().
 */
PolkitBackendAuthority *
polkit_backend_authority_get (void)
{
  PolkitBackendAuthority *authority;

  /* TODO: move to polkitd/main.c */

  /* Announce that we've started in the generic log */
  openlog ("polkitd",
           LOG_PID,
           LOG_DAEMON);  /* system daemons without separate facility value */
  syslog (LOG_INFO, "Started polkitd version %s", VERSION);
  closelog ();

  /* then start logging to the secure log */
  openlog ("polkitd",
           LOG_PID,
           LOG_AUTHPRIV); /* security/authorization messages (private) */

  authority = POLKIT_BACKEND_AUTHORITY (g_object_new (POLKIT_BACKEND_TYPE_JS_AUTHORITY, NULL));

  return authority;
}

/* ---------------------------------------------------------------------------------------------------- */

typedef enum
{
  _COLOR_RESET,
  _COLOR_BOLD_ON,
  _COLOR_INVERSE_ON,
  _COLOR_BOLD_OFF,
  _COLOR_FG_BLACK,
  _COLOR_FG_RED,
  _COLOR_FG_GREEN,
  _COLOR_FG_YELLOW,
  _COLOR_FG_BLUE,
  _COLOR_FG_MAGENTA,
  _COLOR_FG_CYAN,
  _COLOR_FG_WHITE,
  _COLOR_BG_RED,
  _COLOR_BG_GREEN,
  _COLOR_BG_YELLOW,
  _COLOR_BG_BLUE,
  _COLOR_BG_MAGENTA,
  _COLOR_BG_CYAN,
  _COLOR_BG_WHITE
} _Color;

static gboolean _color_stdin_is_tty = FALSE;
static gboolean _color_initialized = FALSE;

static void
_color_init (void)
{
  if (_color_initialized)
    return;
  _color_initialized = TRUE;
  _color_stdin_is_tty = (isatty (STDIN_FILENO) != 0 && isatty (STDOUT_FILENO) != 0);
}

static const gchar *
_color_get (_Color color)
{
  const gchar *str;

  _color_init ();

  if (!_color_stdin_is_tty)
    return "";

  str = NULL;
  switch (color)
    {
    case _COLOR_RESET:      str="\x1b[0m"; break;
    case _COLOR_BOLD_ON:    str="\x1b[1m"; break;
    case _COLOR_INVERSE_ON: str="\x1b[7m"; break;
    case _COLOR_BOLD_OFF:   str="\x1b[22m"; break;
    case _COLOR_FG_BLACK:   str="\x1b[30m"; break;
    case _COLOR_FG_RED:     str="\x1b[31m"; break;
    case _COLOR_FG_GREEN:   str="\x1b[32m"; break;
    case _COLOR_FG_YELLOW:  str="\x1b[33m"; break;
    case _COLOR_FG_BLUE:    str="\x1b[34m"; break;
    case _COLOR_FG_MAGENTA: str="\x1b[35m"; break;
    case _COLOR_FG_CYAN:    str="\x1b[36m"; break;
    case _COLOR_FG_WHITE:   str="\x1b[37m"; break;
    case _COLOR_BG_RED:     str="\x1b[41m"; break;
    case _COLOR_BG_GREEN:   str="\x1b[42m"; break;
    case _COLOR_BG_YELLOW:  str="\x1b[43m"; break;
    case _COLOR_BG_BLUE:    str="\x1b[44m"; break;
    case _COLOR_BG_MAGENTA: str="\x1b[45m"; break;
    case _COLOR_BG_CYAN:    str="\x1b[46m"; break;
    case _COLOR_BG_WHITE:   str="\x1b[47m"; break;
    default:
      g_assert_not_reached ();
      break;
    }
  return str;
}

/* ---------------------------------------------------------------------------------------------------- */

void
polkit_backend_authority_log (PolkitBackendAuthority *authority,
                              const gchar *format,
                              ...)
{
  GTimeVal now;
  time_t now_time;
  struct tm *now_tm;
  gchar time_buf[128];
  gchar *message;
  va_list var_args;

  g_return_if_fail (POLKIT_BACKEND_IS_AUTHORITY (authority));

  va_start (var_args, format);
  message = g_strdup_vprintf (format, var_args);
  va_end (var_args);

  syslog (LOG_NOTICE, "%s", message);

  g_get_current_time (&now);
  now_time = (time_t) now.tv_sec;
  now_tm = localtime (&now_time);
  strftime (time_buf, sizeof time_buf, "%H:%M:%S", now_tm);
  g_print ("%s%s%s.%03d%s: %s\n",
           _color_get (_COLOR_BOLD_ON), _color_get (_COLOR_FG_YELLOW),
           time_buf, (gint) now.tv_usec / 1000,
           _color_get (_COLOR_RESET),
           message);

  g_free (message);
}

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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "polkitauthorizationresult.h"
#include "polkitcheckauthorizationflags.h"
#include "polkitauthority.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitauthority
 * @title: PolkitAuthority
 * @short_description: Authority
 * @stability: Stable
 *
 * #PolkitAuthority is used for checking whether a given subject is
 * authorized to perform a given action. Typically privileged system
 * daemons or suid helpers will use this when handling requests from
 * untrusted clients.
 *
 * User sessions can register an authentication agent with the
 * authority. This is used for requests from untrusted clients where
 * system policy requires that the user needs to acknowledge (through
 * proving he is the user or the administrator) a given action.
 */

/**
 * PolkitAuthority:
 *
 * The #PolkitAuthority struct should not be accessed directly.
 */
struct _PolkitAuthority
{
  /*< private >*/
  GObject parent_instance;

  EggDBusConnection *system_bus;
  EggDBusObjectProxy *authority_object_proxy;

  _PolkitAuthority *real;
};

struct _PolkitAuthorityClass
{
  GObjectClass parent_class;

};

/* TODO: locking */

static PolkitAuthority *the_authority = NULL;

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (PolkitAuthority, polkit_authority, G_TYPE_OBJECT);

static void
real_authority_changed (_PolkitAuthority *real_authority,
                        gpointer user_data)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (user_data);

  g_signal_emit_by_name (authority, "changed");
}

static void
polkit_authority_init (PolkitAuthority *authority)
{
  authority->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  authority->authority_object_proxy = egg_dbus_connection_get_object_proxy (authority->system_bus,
                                                                            "org.freedesktop.PolicyKit1",
                                                                            "/org/freedesktop/PolicyKit1/Authority");

  authority->real = _POLKIT_QUERY_INTERFACE_AUTHORITY (authority->authority_object_proxy);

  g_signal_connect (authority->real,
                    "changed",
                    (GCallback) real_authority_changed,
                    authority);
}

static void
polkit_authority_finalize (GObject *object)
{
  PolkitAuthority *authority;

  authority = POLKIT_AUTHORITY (object);

  g_object_unref (authority->authority_object_proxy);
  g_object_unref (authority->system_bus);

  the_authority = NULL;

  if (G_OBJECT_CLASS (polkit_authority_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_authority_parent_class)->finalize (object);
}

static void
polkit_authority_class_init (PolkitAuthorityClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_authority_finalize;

  /**
   * PolkitAuthority::changed:
   * @authority: A #PolkitAuthority.
   *
   * Emitted when actions and/or authorizations change
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_TYPE_AUTHORITY,
                                          G_SIGNAL_RUN_LAST,
                                          0,                      /* class offset     */
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

/**
 * polkit_authority_get:
 *
 * Gets a reference to the authority.
 *
 * Returns: A #PolkitAuthority. Free it with g_object_unref() when done with it.
 **/
PolkitAuthority *
polkit_authority_get (void)
{
  if (the_authority != NULL)
    goto out;

  the_authority = POLKIT_AUTHORITY (g_object_new (POLKIT_TYPE_AUTHORITY, NULL));

 out:
  return the_authority;
}

static void
generic_cb (GObject      *source_obj,
            GAsyncResult *res,
            gpointer      user_data)
{
  GAsyncResult **target_res = user_data;

  *target_res = g_object_ref (res);
}

static void
generic_async_cb (GObject      *source_obj,
                  GAsyncResult *res,
                  gpointer      user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);

  g_simple_async_result_set_op_res_gpointer (simple, g_object_ref (res), g_object_unref);
  g_simple_async_result_complete (simple);
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_enumerate_actions_async (PolkitAuthority     *authority,
                                          GCancellable        *cancellable,
                                          GAsyncReadyCallback  callback,
                                          gpointer             user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_authority_enumerate_actions_async);

  call_id = _polkit_authority_enumerate_actions (authority->real,
                                                 EGG_DBUS_CALL_FLAGS_NONE,
                                                 "", /* TODO: use current locale */
                                                 cancellable,
                                                 generic_async_cb,
                                                 simple);

  return call_id;
}

/**
 * polkit_authority_enumerate_actions:
 * @authority: A #PolkitAuthority.
 * @cancellable: A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously retrieves all registered actions.
 *
 * When the operation is finished, @callback will be invoked. You can then
 * call polkit_authority_enumerate_actions_finish() to get the result of
 * the operation.
 **/
void
polkit_authority_enumerate_actions (PolkitAuthority     *authority,
                                    GCancellable        *cancellable,
                                    GAsyncReadyCallback  callback,
                                    gpointer             user_data)
{
  polkit_authority_enumerate_actions_async (authority, cancellable, callback, user_data);
}

/**
 * polkit_authority_enumerate_actions_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: Return location for error or %NULL.
 *
 * Finishes retrieving all registered actions.
 *
 * Returns: A list of #PolkitActionDescription objects or %NULL if @error is set. The returned list
 * should be freed with g_list_free() after each element have been freed with g_object_unref().
 **/
GList *
polkit_authority_enumerate_actions_finish (PolkitAuthority *authority,
                                           GAsyncResult    *res,
                                           GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_enumerate_actions_async);

  result = NULL;

  if (!_polkit_authority_enumerate_actions_finish (authority->real,
                                                   &array_seq,
                                                   real_res,
                                                   error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitActionDescription *real_ad;

      real_ad = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_action_description_new_for_real (real_ad));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  g_object_unref (real_res);
  return result;
}


/**
 * polkit_authority_enumerate_actions_sync:
 * @authority: A #PolkitAuthority.
 * @cancellable: A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Synchronously retrieves all registered actions.
 *
 * Returns: A list of #PolkitActionDescription or %NULL if @error is set. The returned list
 * should be freed with g_list_free() after each element have been freed with g_object_unref().
 **/
GList *
polkit_authority_enumerate_actions_sync (PolkitAuthority *authority,
                                         GCancellable    *cancellable,
                                         GError         **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_enumerate_actions_async (authority, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  result = polkit_authority_enumerate_actions_finish (authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */
static guint
polkit_authority_check_authorization_async (PolkitAuthority               *authority,
                                            PolkitSubject                 *subject,
                                            const gchar                   *action_id,
                                            PolkitCheckAuthorizationFlags  flags,
                                            GCancellable                  *cancellable,
                                            GAsyncReadyCallback            callback,
                                            gpointer                       user_data)
{
  _PolkitSubject *real_subject;
  guint call_id;
  GSimpleAsyncResult *simple;

  real_subject = polkit_subject_get_real (subject);

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_authority_check_authorization_async);

  call_id = _polkit_authority_check_authorization (authority->real,
                                                   EGG_DBUS_CALL_FLAGS_NONE,
                                                   real_subject,
                                                   action_id,
                                                   flags,
                                                   cancellable,
                                                   generic_async_cb,
                                                   simple);

  g_object_unref (real_subject);

  return call_id;
}

/**
 * polkit_authority_check_authorization:
 * @authority: A #PolkitAuthority.
 * @subject: A #PolkitSubject.
 * @action_id: The action to check for.
 * @flags: A set of #PolkitCheckAuthorizationFlags.
 * @cancellable: A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously checks if @subject is authorized to perform the action represented
 * by @action_id.
 *
 * When the operation is finished, @callback will be invoked. You can then
 * call polkit_authority_check_authorization_finish() to get the result of
 * the operation.
 **/
void
polkit_authority_check_authorization (PolkitAuthority               *authority,
                                      PolkitSubject                 *subject,
                                      const gchar                   *action_id,
                                      PolkitCheckAuthorizationFlags  flags,
                                      GCancellable                  *cancellable,
                                      GAsyncReadyCallback            callback,
                                      gpointer                       user_data)
{
  polkit_authority_check_authorization_async (authority,
                                              subject,
                                              action_id,
                                              flags,
                                              cancellable,
                                              callback,
                                              user_data);
}

/**
 * polkit_authority_check_authorization_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: Return location for error or %NULL.
 *
 * Finishes checking if a subject is authorized for an action.
 *
 * Returns: A #PolkitAuthorizationResult.
 **/
PolkitAuthorizationResult
polkit_authority_check_authorization_finish (PolkitAuthority          *authority,
                                             GAsyncResult             *res,
                                             GError                  **error)
{
  _PolkitAuthorizationResult result;
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_check_authorization_async);

  result = _POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

  if (!_polkit_authority_check_authorization_finish (authority->real,
                                             &result,
                                             real_res,
                                             error))
    goto out;

 out:
  g_object_unref (real_res);
  return result;
}

/**
 * polkit_authority_check_authorization:
 * @authority: A #PolkitAuthority.
 * @subject: A #PolkitSubject.
 * @action_id: The action to check for.
 * @flags: A set of #PolkitCheckAuthorizationFlags.
 * @cancellable: A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Checks if @subject is authorized to perform the action represented by @action_id.
 *
 * Returns: A #PolkitAuthorizationResult.
 */
PolkitAuthorizationResult
polkit_authority_check_authorization_sync (PolkitAuthority               *authority,
                                           PolkitSubject                 *subject,
                                           const gchar                   *action_id,
                                           PolkitCheckAuthorizationFlags  flags,
                                           GCancellable                  *cancellable,
                                           GError                       **error)
{
  guint call_id;
  GAsyncResult *res;
  PolkitAuthorizationResult result;

  call_id = polkit_authority_check_authorization_async (authority,
                                                        subject,
                                                        action_id,
                                                        flags,
                                                        cancellable,
                                                        generic_cb,
                                                        &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  result = polkit_authority_check_authorization_finish (authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_register_authentication_agent_async (PolkitAuthority      *authority,
                                                      const gchar          *session_id,
                                                      const gchar          *object_path,
                                                      GCancellable         *cancellable,
                                                      GAsyncReadyCallback   callback,
                                                      gpointer              user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_authority_register_authentication_agent_async);

  call_id = _polkit_authority_register_authentication_agent (authority->real,
                                                             EGG_DBUS_CALL_FLAGS_NONE,
                                                             session_id,
                                                             object_path,
                                                             cancellable,
                                                             generic_async_cb,
                                                             simple);

  return call_id;
}

/**
 * polkit_authority_register_authentication_agent:
 * @authority: A #PolkitAuthority.
 * @session_id: The identifier of the session to register for or %NULL for the session of the caller.
 * @object_path: The object path for the authentication agent.
 * @cancellable: A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously registers an authentication agent.
 *
 * When the operation is finished, @callback will be invoked. You can then
 * call polkit_authority_register_authentication_agent_finish() to get the result of
 * the operation.
 **/
void
polkit_authority_register_authentication_agent (PolkitAuthority      *authority,
                                                const gchar          *session_id,
                                                const gchar          *object_path,
                                                GCancellable         *cancellable,
                                                GAsyncReadyCallback   callback,
                                                gpointer              user_data)
{
  polkit_authority_register_authentication_agent_async (authority,
                                                        session_id,
                                                        object_path,
                                                        cancellable,
                                                        callback,
                                                        user_data);
}

/**
 * polkit_authority_register_authentication_agent_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: Return location for error or %NULL.
 *
 * Finishes registering an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_register_authentication_agent_finish (PolkitAuthority *authority,
                                                       GAsyncResult    *res,
                                                       GError         **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_register_authentication_agent_async);

  ret = _polkit_authority_register_authentication_agent_finish (authority->real,
                                                                real_res,
                                                                error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}


/**
 * polkit_authority_register_authentication_agent_sync:
 * @authority: A #PolkitAuthority.
 * @session_id: The identifier of the session to register for or %NULL for the session of the caller.
 * @object_path: The object path for the authentication agent.
 * @cancellable: A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Registers an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_register_authentication_agent_sync (PolkitAuthority     *authority,
                                                     const gchar         *session_id,
                                                     const gchar         *object_path,
                                                     GCancellable        *cancellable,
                                                     GError             **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_authority_register_authentication_agent_async (authority,
                                                                  session_id,
                                                                  object_path,
                                                                  cancellable,
                                                                  generic_cb,
                                                                  &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  ret = polkit_authority_register_authentication_agent_finish (authority, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_unregister_authentication_agent_async (PolkitAuthority      *authority,
                                                        const gchar          *session_id,
                                                        const gchar          *object_path,
                                                        GCancellable         *cancellable,
                                                        GAsyncReadyCallback   callback,
                                                        gpointer              user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_authority_unregister_authentication_agent_async);

  call_id = _polkit_authority_unregister_authentication_agent (authority->real,
                                                               EGG_DBUS_CALL_FLAGS_NONE,
                                                               session_id,
                                                               object_path,
                                                               cancellable,
                                                               generic_async_cb,
                                                               simple);

  return call_id;
}

/**
 * polkit_authority_unregister_authentication_agent:
 * @authority: A #PolkitAuthority.
 * @session_id: The identifier of the session the agent is registered at or %NULL for the session of the caller.
 * @object_path: The object path that the authentication agent is registered at.
 * @cancellable: A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously unregisters an authentication agent.
 *
 * When the operation is finished, @callback will be invoked. You can then
 * call polkit_authority_unregister_authentication_agent_finish() to get the result of
 * the operation.
 **/
void
polkit_authority_unregister_authentication_agent (PolkitAuthority      *authority,
                                                  const gchar          *session_id,
                                                  const gchar          *object_path,
                                                  GCancellable         *cancellable,
                                                  GAsyncReadyCallback   callback,
                                                  gpointer              user_data)
{
  polkit_authority_unregister_authentication_agent_async (authority,
                                                          session_id,
                                                          object_path,
                                                          cancellable,
                                                          callback,
                                                          user_data);
}

/**
 * polkit_authority_unregister_authentication_agent_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: Return location for error or %NULL.
 *
 * Finishes unregistering an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully unregistered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_unregister_authentication_agent_finish (PolkitAuthority *authority,
                                                         GAsyncResult    *res,
                                                         GError         **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_unregister_authentication_agent_async);

  ret = _polkit_authority_unregister_authentication_agent_finish (authority->real,
                                                                real_res,
                                                                error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}

/**
 * polkit_authority_unregister_authentication_agent_sync:
 * @authority: A #PolkitAuthority.
 * @session_id: The identifier of the session the agent is registered at or %NULL for the session of the caller.
 * @object_path: The object path that the authentication agent is registered at.
 * @cancellable: A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Unregisters an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully unregistered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_unregister_authentication_agent_sync (PolkitAuthority     *authority,
                                                       const gchar         *session_id,
                                                       const gchar         *object_path,
                                                       GCancellable        *cancellable,
                                                       GError             **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_authority_unregister_authentication_agent_async (authority,
                                                                    session_id,
                                                                    object_path,
                                                                    cancellable,
                                                                    generic_cb,
                                                                    &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  ret = polkit_authority_unregister_authentication_agent_finish (authority, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_authentication_agent_response_async (PolkitAuthority      *authority,
                                                      const gchar          *cookie,
                                                      PolkitIdentity       *identity,
                                                      GCancellable         *cancellable,
                                                      GAsyncReadyCallback   callback,
                                                      gpointer              user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      polkit_authority_authentication_agent_response_async);

  real_identity = polkit_identity_get_real (identity);

  call_id = _polkit_authority_authentication_agent_response (authority->real,
                                                             EGG_DBUS_CALL_FLAGS_NONE,
                                                             cookie,
                                                             real_identity,
                                                             cancellable,
                                                             generic_async_cb,
                                                             simple);

  g_object_unref (real_identity);

  return call_id;
}

/**
 * polkit_authority_authentication_agent_response:
 * @authority: A #PolkitAuthority.
 * @cookie: The cookie passed to the authentication agent from the authority.
 * @identity: The identity that was authenticated.
 * @cancellable: A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously provide response that @identity successfully authenticated
 * for the authentication request identified by @cookie.
 *
 * This function is only used by the privileged bits of an authentication agent.
 * It will fail if the caller is not sufficiently privileged (typically uid 0).
 *
 * When the operation is finished, @callback will be invoked. You can then
 * call polkit_authority_authentication_agent_response_finish() to get the result of
 * the operation.
 **/
void
polkit_authority_authentication_agent_response (PolkitAuthority      *authority,
                                                const gchar          *cookie,
                                                PolkitIdentity       *identity,
                                                GCancellable         *cancellable,
                                                GAsyncReadyCallback   callback,
                                                gpointer              user_data)
{
  polkit_authority_authentication_agent_response_async (authority,
                                                        cookie,
                                                        identity,
                                                        cancellable,
                                                        callback,
                                                        user_data);
}

/**
 * polkit_authority_authentication_agent_response_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: Return location for error or %NULL.
 *
 * Finishes providing response from an authentication agent.
 *
 * Returns: %TRUE if @authority acknowledged the call, %FALSE if @error is set.
 **/
gboolean
polkit_authority_authentication_agent_response_finish (PolkitAuthority *authority,
                                                       GAsyncResult    *res,
                                                       GError         **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_authentication_agent_response_async);

  ret = _polkit_authority_authentication_agent_response_finish (authority->real,
                                                                real_res,
                                                                error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}


/**
 * polkit_authority_authentication_agent_response_sync:
 * @authority: A #PolkitAuthority.
 * @cookie: The cookie passed to the authentication agent from the authority.
 * @identity: The identity that was authenticated.
 * @cancellable: A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Provide response that @identity successfully authenticated for the
 * authentication request identified by @cookie. See polkit_authority_authentication_agent_response()
 * for limitations on who is allowed is to call this method.
 *
 * Returns: %TRUE if @authority acknowledged the call, %FALSE if @error is set.
 **/
gboolean
polkit_authority_authentication_agent_response_sync (PolkitAuthority     *authority,
                                                     const gchar         *cookie,
                                                     PolkitIdentity      *identity,
                                                     GCancellable        *cancellable,
                                                     GError             **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_authority_authentication_agent_response_async (authority,
                                                                  cookie,
                                                                  identity,
                                                                  cancellable,
                                                                  generic_cb,
                                                                  &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  ret = polkit_authority_authentication_agent_response_finish (authority, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

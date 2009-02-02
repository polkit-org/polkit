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

GList *
polkit_backend_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                            PolkitSubject            *caller,
                                            const gchar              *locale,
                                            GCancellable             *cancellable,
                                            GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->enumerate_actions (authority, caller, locale, cancellable, error);
}

GList *
polkit_backend_authority_enumerate_users (PolkitBackendAuthority   *authority,
                                          PolkitSubject            *caller,
                                          GCancellable             *cancellable,
                                          GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->enumerate_users (authority, caller, cancellable, error);
}

GList *
polkit_backend_authority_enumerate_groups (PolkitBackendAuthority   *authority,
                                           PolkitSubject            *caller,
                                           GCancellable             *cancellable,
                                           GError                  **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->enumerate_groups (authority, caller, cancellable, error);
}

void
polkit_backend_authority_check_authorization (PolkitBackendAuthority        *authority,
                                              PolkitSubject                 *caller,
                                              PolkitSubject                 *subject,
                                              const gchar                   *action_id,
                                              PolkitCheckAuthorizationFlags  flags,
                                              GCancellable                  *cancellable,
                                              GAsyncReadyCallback            callback,
                                              gpointer                       user_data)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->check_authorization (authority, caller, subject, action_id, flags, cancellable, callback, user_data);
}

PolkitAuthorizationResult
polkit_backend_authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                                     GAsyncResult            *res,
                                                     GError                 **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->check_authorization_finish (authority, res, error);
}

GList *
polkit_backend_authority_enumerate_authorizations  (PolkitBackendAuthority    *authority,
                                                    PolkitSubject             *caller,
                                                    PolkitIdentity            *identity,
                                                    GCancellable              *cancellable,
                                                    GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->enumerate_authorizations (authority, caller, identity, cancellable, error);
}

gboolean
polkit_backend_authority_add_authorization  (PolkitBackendAuthority    *authority,
                                             PolkitSubject             *caller,
                                             PolkitIdentity            *identity,
                                             PolkitAuthorization       *authorization,
                                             GCancellable              *cancellable,
                                             GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->add_authorization (authority, caller, identity, authorization, cancellable, error);
}

gboolean
polkit_backend_authority_remove_authorization  (PolkitBackendAuthority    *authority,
                                                PolkitSubject             *caller,
                                                PolkitIdentity            *identity,
                                                PolkitAuthorization       *authorization,
                                                GCancellable              *cancellable,
                                                GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->remove_authorization (authority, caller, identity, authorization, cancellable, error);
}

gboolean
polkit_backend_authority_register_authentication_agent (PolkitBackendAuthority    *authority,
                                                        PolkitSubject             *caller,
                                                        const gchar               *object_path,
                                                        GCancellable              *cancellable,
                                                        GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->register_authentication_agent (authority, caller, object_path, cancellable, error);
}

gboolean
polkit_backend_authority_unregister_authentication_agent (PolkitBackendAuthority    *authority,
                                                          PolkitSubject             *caller,
                                                          const gchar               *object_path,
                                                          GCancellable              *cancellable,
                                                          GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->unregister_authentication_agent (authority, caller, object_path, cancellable, error);
}

gboolean
polkit_backend_authority_authentication_agent_response (PolkitBackendAuthority    *authority,
                                                        PolkitSubject             *caller,
                                                        const gchar               *cookie,
                                                        PolkitIdentity            *identity,
                                                        GCancellable              *cancellable,
                                                        GError                   **error)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  return klass->authentication_agent_response (authority, caller, cookie, identity, cancellable, error);
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
  PolkitSubject *caller;
  EggDBusArraySeq *array;
  GError *error;
  GList *actions;
  GList *l;

  error = NULL;
  caller = NULL;
  actions = NULL;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  actions = polkit_backend_authority_enumerate_actions (server->authority,
                                                        caller,
                                                        locale,
                                                        NULL,
                                                        &error);
  if (error != NULL)
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

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

  _polkit_authority_handle_enumerate_actions_finish (method_invocation, array);

  g_object_unref (array);

 out:
  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);
  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_enumerate_users (_PolkitAuthorityManager *instance,
                                          EggDBusMethodInvocation *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  EggDBusArraySeq *array;
  GError *error;
  GList *identities;
  GList *l;

  error = NULL;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  identities = polkit_backend_authority_enumerate_users (server->authority,
                                                         caller,
                                                         NULL,
                                                         &error);
  if (error != NULL)
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_IDENTITY,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      _PolkitIdentity *real;

      real = polkit_identity_get_real (identity);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_manager_handle_enumerate_users_finish (method_invocation, array);

  g_object_unref (array);

 out:

  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);

  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_enumerate_groups (_PolkitAuthorityManager *instance,
                                           EggDBusMethodInvocation *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  EggDBusArraySeq *array;
  GError *error;
  GList *identities;
  GList *l;

  error = NULL;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  identities = polkit_backend_authority_enumerate_groups (server->authority,
                                                          caller,
                                                          NULL,
                                                          &error);
  if (error != NULL)
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_IDENTITY,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      _PolkitIdentity *real;

      real = polkit_identity_get_real (identity);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_manager_handle_enumerate_groups_finish (method_invocation, array);

  g_object_unref (array);

 out:

  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);

  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
check_auth_cb (GObject      *source_object,
               GAsyncResult *res,
               gpointer      user_data)
{
  EggDBusMethodInvocation *method_invocation = EGG_DBUS_METHOD_INVOCATION (user_data);
  PolkitAuthorizationResult result;
  GError *error;

  error = NULL;
  result = polkit_backend_authority_check_authorization_finish (POLKIT_BACKEND_AUTHORITY (source_object),
                                                                res,
                                                                &error);
  if (error != NULL)
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
    }
  else
    {
      _polkit_authority_handle_check_authorization_finish (method_invocation, result);
    }
}

static void
authority_handle_check_authorization (_PolkitAuthority               *instance,
                                      _PolkitSubject                 *real_subject,
                                      const gchar                    *action_id,
                                      _PolkitCheckAuthorizationFlags  flags,
                                      EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *subject;
  PolkitSubject *caller;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  subject = polkit_subject_new_for_real (real_subject);

  g_object_set_data_full (G_OBJECT (method_invocation), "caller", caller, (GDestroyNotify) g_object_unref);
  g_object_set_data_full (G_OBJECT (method_invocation), "subject", subject, (GDestroyNotify) g_object_unref);

  polkit_backend_authority_check_authorization (server->authority,
                                                caller,
                                                subject,
                                                action_id,
                                                flags,
                                                NULL, /* TODO: use cancellable */
                                                check_auth_cb,
                                                method_invocation);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_enumerate_authorizations (_PolkitAuthorityManager        *instance,
                                                   _PolkitIdentity                *real_identity,
                                                   EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  PolkitIdentity *identity;
  EggDBusArraySeq *array;
  GError *error;
  GList *authorizations;
  GList *l;

  error = NULL;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  identity = polkit_identity_new_for_real (real_identity);

  authorizations = polkit_backend_authority_enumerate_authorizations (server->authority,
                                                                      caller,
                                                                      identity,
                                                                      NULL,
                                                                      &error);

  if (error != NULL)
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  array = egg_dbus_array_seq_new (G_TYPE_OBJECT, //_POLKIT_TYPE_IDENTITY,
                                  (GDestroyNotify) g_object_unref,
                                  NULL,
                                  NULL);

  for (l = authorizations; l != NULL; l = l->next)
    {
      PolkitAuthorization *authorization = POLKIT_AUTHORIZATION (l->data);
      _PolkitAuthorization *real;

      real = polkit_authorization_get_real (authorization);
      egg_dbus_array_seq_add (array, real);
    }

  _polkit_authority_manager_handle_enumerate_authorizations_finish (method_invocation, array);

  g_object_unref (array);

 out:

  g_list_foreach (authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (authorizations);

  g_object_unref (caller);

  g_object_unref (identity);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_add_authorization (_PolkitAuthorityManager        *instance,
                                            _PolkitIdentity                *real_identity,
                                            _PolkitAuthorization           *real_authorization,
                                            EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  PolkitIdentity *identity;
  PolkitAuthorization *authorization;
  GError *error;


  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  identity = polkit_identity_new_for_real (real_identity);

  authorization = polkit_authorization_new_for_real (real_authorization);

  error = NULL;
  if (!polkit_backend_authority_add_authorization (server->authority,
                                                   caller,
                                                   identity,
                                                   authorization,
                                                   NULL,
                                                   &error))
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  _polkit_authority_manager_handle_add_authorization_finish (method_invocation);

 out:
  g_object_unref (authorization);
  g_object_unref (identity);
  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_manager_handle_remove_authorization (_PolkitAuthorityManager        *instance,
                                               _PolkitIdentity                *real_identity,
                                               _PolkitAuthorization           *real_authorization,
                                               EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  PolkitIdentity *identity;
  PolkitAuthorization *authorization;
  GError *error;


  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  identity = polkit_identity_new_for_real (real_identity);

  authorization = polkit_authorization_new_for_real (real_authorization);

  error = NULL;
  if (!polkit_backend_authority_remove_authorization (server->authority,
                                                      caller,
                                                      identity,
                                                      authorization,
                                                      NULL,
                                                      &error))
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  _polkit_authority_manager_handle_remove_authorization_finish (method_invocation);

 out:
  g_object_unref (authorization);
  g_object_unref (identity);
  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_register_authentication_agent (_PolkitAuthority               *instance,
                                                const gchar                    *object_path,
                                                EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  GError *error;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  error = NULL;
  if (!polkit_backend_authority_register_authentication_agent (server->authority,
                                                               caller,
                                                               object_path,
                                                               NULL,
                                                               &error))
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  _polkit_authority_handle_register_authentication_agent_finish (method_invocation);

 out:
  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_unregister_authentication_agent (_PolkitAuthority               *instance,
                                                  const gchar                    *object_path,
                                                  EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  GError *error;

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  error = NULL;
  if (!polkit_backend_authority_unregister_authentication_agent (server->authority,
                                                                 caller,
                                                                 object_path,
                                                                 NULL,
                                                                 &error))
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  _polkit_authority_handle_unregister_authentication_agent_finish (method_invocation);

 out:
  g_object_unref (caller);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
authority_handle_authentication_agent_response (_PolkitAuthority               *instance,
                                                const gchar                    *cookie,
                                                _PolkitIdentity                *real_identity,
                                                EggDBusMethodInvocation        *method_invocation)
{
  Server *server = SERVER (instance);
  PolkitSubject *caller;
  PolkitIdentity *identity;
  GError *error;

  identity = polkit_identity_new_for_real (real_identity);

  caller = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (method_invocation));

  error = NULL;
  if (!polkit_backend_authority_authentication_agent_response (server->authority,
                                                               caller,
                                                               cookie,
                                                               identity,
                                                               NULL,
                                                               &error))
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
      g_error_free (error);
      goto out;
    }

  _polkit_authority_handle_authentication_agent_response_finish (method_invocation);

 out:
  g_object_unref (caller);

  g_object_unref (identity);
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

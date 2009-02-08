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

#if !defined (_POLKIT_BACKEND_COMPILATION) && !defined(_POLKIT_BACKEND_INSIDE_POLKIT_BACKEND_H)
#error "Only <polkitbackend/polkitbackend.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_BACKEND_AUTHORITY_H
#define __POLKIT_BACKEND_AUTHORITY_H

#include <glib-object.h>
#include "polkitbackendtypes.h"

G_BEGIN_DECLS

#define POLKIT_BACKEND_TYPE_AUTHORITY         (polkit_backend_authority_get_type ())
#define POLKIT_BACKEND_AUTHORITY(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_BACKEND_TYPE_AUTHORITY, PolkitBackendAuthority))
#define POLKIT_BACKEND_AUTHORITY_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_BACKEND_TYPE_AUTHORITY, PolkitBackendAuthorityClass))
#define POLKIT_BACKEND_AUTHORITY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_BACKEND_TYPE_AUTHORITY,PolkitBackendAuthorityClass))
#define POLKIT_BACKEND_IS_AUTHORITY(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_BACKEND_TYPE_AUTHORITY))
#define POLKIT_BACKEND_IS_AUTHORITY_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_BACKEND_TYPE_AUTHORITY))

typedef struct _PolkitBackendAuthorityClass    PolkitBackendAuthorityClass;

/**
 * POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME:
 *
 * Extension point name for authority backend implementations.
 */
#define POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME "polkit-backend-authority-1"

/**
 * PolkitBackendAuthority:
 *
 * The #PolkitBackendAuthority struct should not be accessed directly.
 */
struct _PolkitBackendAuthority
{
  GObject parent_instance;
};

/**
 * PolkitBackendAuthorityClass:
 * @parent_class: The parent class.
 * @changed: Function pointer for #PolkitBackendAuthorityClass::changed signal.
 * @enumerate_actions: Enumerates registered actions on the
 * system. See polkit_backend_authority_enumerate_actions() for
 * details.
 * @check_authorization: Called to initiate an asynchronous
 * authorization check. See
 * polkit_backend_authority_check_authorization() for details.
 * @check_authorization_finish: Called when finishing an authorization
 * check. See polkit_backend_authority_check_authorization_finish()
 * for details.
 * @register_authentication_agent: Called when an authentication agent
 * is attempting to register or %NULL if the backend doesn't support
 * the operation. See
 * polkit_backend_authority_register_authentication_agent() for
 * details.
 * @unregister_authentication_agent: Called when an authentication
 * agent is attempting to unregister or %NULL if the backend doesn't
 * support the operation. See
 * polkit_backend_authority_unregister_authentication_agent() for
 * details.
 * @authentication_agent_response: Called by an authentication agent
 * when the user successfully authenticates or %NULL if the backend
 * doesn't support the operation. See
 * polkit_backend_authority_authentication_agent_response() for
 * details.
 * @enumerate_users: Enumerates users on the system or %NULL if the
 * backend doesn't support the operation. See
 * polkit_backend_authority_enumerate_users() for details.
 * @enumerate_groups: Enumerates groups on the system or %NULL if the
 * backend doesn't support the operation. See
 * polkit_backend_authority_enumerate_groups() for details.
 * @enumerate_authorizations: Enumerates authorizations for a given
 * identity or %NULL if the backend doesn't support the operation. See
 * polkit_backend_authority_enumerate_authorizations() for details.
 * @add_authorization: Add an authorization to a given identity or
 * %NULL if the backend doesn't support the operation. See
 * polkit_backend_authority_add_authorization() for details.
 * @remove_authorization: Remove an authorization for a given identity
 * or %NULL if the backend doesn't support the operation. See
 * polkit_backend_authority_remove_authorization() for details.
 * @system_bus_name_owner_changed: temporary VFunc, to be removed before 1.0.
 *
 * VFuncs that authority backends need to implement.
 */
struct _PolkitBackendAuthorityClass
{
  /*< public >*/
  GObjectClass parent_class;

  /* Signals */
  void (*changed)  (PolkitBackendAuthority   *authority);

  /* VTable */

  GList *(*enumerate_actions)  (PolkitBackendAuthority   *authority,
                                PolkitSubject            *caller,
                                const gchar              *locale,
                                GError                  **error);

  void (*check_authorization) (PolkitBackendAuthority        *authority,
                               PolkitSubject                 *caller,
                               PolkitSubject                 *subject,
                               const gchar                   *action_id,
                               PolkitCheckAuthorizationFlags  flags,
                               GCancellable                  *cancellable,
                               GAsyncReadyCallback            callback,
                               gpointer                       user_data);

  PolkitAuthorizationResult (*check_authorization_finish) (PolkitBackendAuthority  *authority,
                                                           GAsyncResult            *res,
                                                           GError                 **error);

  gboolean (*register_authentication_agent) (PolkitBackendAuthority   *authority,
                                             PolkitSubject            *caller,
                                             const gchar              *session_id,
                                             const gchar              *object_path,
                                             GError                  **error);

  gboolean (*unregister_authentication_agent) (PolkitBackendAuthority   *authority,
                                               PolkitSubject            *caller,
                                               const gchar              *session_id,
                                               const gchar              *object_path,
                                               GError                  **error);

  gboolean (*authentication_agent_response) (PolkitBackendAuthority   *authority,
                                             PolkitSubject            *caller,
                                             const gchar              *cookie,
                                             PolkitIdentity           *identity,
                                             GError                  **error);

  GList *(*enumerate_users)    (PolkitBackendAuthority   *authority,
                                PolkitSubject            *caller,
                                GError                  **error);

  GList *(*enumerate_groups)   (PolkitBackendAuthority   *authority,
                                PolkitSubject            *caller,
                                GError                  **error);

  GList *(*enumerate_authorizations) (PolkitBackendAuthority   *authority,
                                      PolkitSubject            *caller,
                                      PolkitIdentity           *identity,
                                      GError                  **error);

  gboolean (*add_authorization) (PolkitBackendAuthority   *authority,
                                 PolkitSubject            *caller,
                                 PolkitIdentity           *identity,
                                 PolkitAuthorization      *authorization,
                                 GError                  **error);

  gboolean (*remove_authorization) (PolkitBackendAuthority   *authority,
                                    PolkitSubject            *caller,
                                    PolkitIdentity           *identity,
                                    PolkitAuthorization      *authorization,
                                    GError                  **error);

  /* TODO: need something more efficient such that we don't watch all name changes */
  void (*system_bus_name_owner_changed)  (PolkitBackendAuthority   *authority,
                                          const gchar              *name,
                                          const gchar              *old_owner,
                                          const gchar              *new_owner);

  /*< private >*/
  /* Padding for future expansion */
  void (*_polkit_reserved1) (void);
  void (*_polkit_reserved2) (void);
  void (*_polkit_reserved3) (void);
  void (*_polkit_reserved4) (void);
  void (*_polkit_reserved5) (void);
  void (*_polkit_reserved6) (void);
  void (*_polkit_reserved7) (void);
  void (*_polkit_reserved8) (void);
};

GType    polkit_backend_authority_get_type (void) G_GNUC_CONST;

/* --- */

void     polkit_backend_authority_system_bus_name_owner_changed (PolkitBackendAuthority   *authority,
                                                                 const gchar              *name,
                                                                 const gchar              *old_owner,
                                                                 const gchar              *new_owner);

GList   *polkit_backend_authority_enumerate_actions         (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             const gchar               *locale,
                                                             GError                   **error);

GList   *polkit_backend_authority_enumerate_users           (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             GError                   **error);

GList   *polkit_backend_authority_enumerate_groups          (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             GError                   **error);

void     polkit_backend_authority_check_authorization       (PolkitBackendAuthority        *authority,
                                                             PolkitSubject                 *caller,
                                                             PolkitSubject                 *subject,
                                                             const gchar                   *action_id,
                                                             PolkitCheckAuthorizationFlags  flags,
                                                             GCancellable                  *cancellable,
                                                             GAsyncReadyCallback            callback,
                                                             gpointer                       user_data);

PolkitAuthorizationResult polkit_backend_authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                                                               GAsyncResult            *res,
                                                                               GError                 **error);

GList   *polkit_backend_authority_enumerate_authorizations  (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             PolkitIdentity            *identity,
                                                             GError                   **error);

gboolean polkit_backend_authority_add_authorization         (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             PolkitIdentity            *identity,
                                                             PolkitAuthorization       *authorization,
                                                             GError                   **error);

gboolean polkit_backend_authority_remove_authorization      (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             PolkitIdentity            *identity,
                                                             PolkitAuthorization       *authorization,
                                                             GError                   **error);

gboolean polkit_backend_authority_register_authentication_agent (PolkitBackendAuthority    *authority,
                                                                 PolkitSubject             *caller,
                                                                 const gchar               *session_id,
                                                                 const gchar               *object_path,
                                                                 GError                   **error);

gboolean polkit_backend_authority_unregister_authentication_agent (PolkitBackendAuthority    *authority,
                                                                   PolkitSubject             *caller,
                                                                   const gchar               *session_id,
                                                                   const gchar               *object_path,
                                                                   GError                   **error);

gboolean polkit_backend_authority_authentication_agent_response (PolkitBackendAuthority    *authority,
                                                                 PolkitSubject             *caller,
                                                                 const gchar               *cookie,
                                                                 PolkitIdentity            *identity,
                                                                 GError                   **error);

/* --- */

PolkitBackendAuthority *polkit_backend_authority_get (void);

gboolean polkit_backend_register_authority (PolkitBackendAuthority   *authority,
                                            const gchar              *well_known_name,
                                            const gchar              *object_path,
                                            GError                  **error);

G_END_DECLS

#endif /* __POLKIT_BACKEND_AUTHORITY_H */

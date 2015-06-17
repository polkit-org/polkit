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

#include <polkit/polkit.h>
#include <polkitbackend/polkitbackendtypes.h>

G_BEGIN_DECLS

#define POLKIT_BACKEND_TYPE_AUTHORITY         (polkit_backend_authority_get_type ())
#define POLKIT_BACKEND_AUTHORITY(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_BACKEND_TYPE_AUTHORITY, PolkitBackendAuthority))
#define POLKIT_BACKEND_AUTHORITY_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_BACKEND_TYPE_AUTHORITY, PolkitBackendAuthorityClass))
#define POLKIT_BACKEND_AUTHORITY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_BACKEND_TYPE_AUTHORITY,PolkitBackendAuthorityClass))
#define POLKIT_BACKEND_IS_AUTHORITY(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_BACKEND_TYPE_AUTHORITY))
#define POLKIT_BACKEND_IS_AUTHORITY_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_BACKEND_TYPE_AUTHORITY))

typedef struct _PolkitBackendAuthorityClass    PolkitBackendAuthorityClass;

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
 * @get_name: Function pointer for the polkit_backend_authority_get_name() function.
 * @get_version: Function pointer for the polkit_backend_authority_get_version() function.
 * @get_features: Function pointer for the polkit_backend_authority_get_features() function.
 * @changed: Function pointer for #PolkitBackendAuthority::changed signal.
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
 * @enumerate_temporary_authorizations: Called to enumerate temporary
 * authorizations or %NULL if the backend doesn't support the operation.
 * See polkit_backend_authority_enumerate_temporary_authorizations()
 * for details.
 * @revoke_temporary_authorizations: Called to revoke temporary
 * authorizations or %NULL if the backend doesn't support the operation.
 * See polkit_backend_authority_revoke_temporary_authorizations()
 * for details.
 * @revoke_temporary_authorization_by_id: Called to revoke a temporary
 * authorization identified by id or %NULL if the backend doesn't support
 * the operation. See polkit_backend_authority_revoke_temporary_authorization_by_id()
 * for details.
 *
 * Class structure for #PolkitBackendAuthority.
 */
struct _PolkitBackendAuthorityClass
{
  /*< public >*/
  GObjectClass parent_class;

  /* Signals */
  void (*changed)  (PolkitBackendAuthority   *authority);

  /* VTable */

  const gchar             *(*get_name)     (PolkitBackendAuthority *authority);
  const gchar             *(*get_version)  (PolkitBackendAuthority *authority);
  PolkitAuthorityFeatures  (*get_features) (PolkitBackendAuthority *authority);

  GList *(*enumerate_actions)  (PolkitBackendAuthority   *authority,
                                PolkitSubject            *caller,
                                const gchar              *locale,
                                GError                  **error);

  void (*check_authorization) (PolkitBackendAuthority        *authority,
                               PolkitSubject                 *caller,
                               PolkitSubject                 *subject,
                               const gchar                   *action_id,
                               PolkitDetails                 *details,
                               PolkitCheckAuthorizationFlags  flags,
                               GCancellable                  *cancellable,
                               GAsyncReadyCallback            callback,
                               gpointer                       user_data);

  PolkitAuthorizationResult * (*check_authorization_finish) (PolkitBackendAuthority  *authority,
                                                             GAsyncResult            *res,
                                                             GError                 **error);

  gboolean (*register_authentication_agent) (PolkitBackendAuthority   *authority,
                                             PolkitSubject            *caller,
                                             PolkitSubject            *subject,
                                             const gchar              *locale,
                                             const gchar              *object_path,
                                             GVariant                 *options,
                                             GError                  **error);

  gboolean (*unregister_authentication_agent) (PolkitBackendAuthority   *authority,
                                               PolkitSubject            *caller,
                                               PolkitSubject            *subject,
                                               const gchar              *object_path,
                                               GError                  **error);

  gboolean (*authentication_agent_response) (PolkitBackendAuthority   *authority,
                                             PolkitSubject            *caller,
                                             uid_t                     uid,
                                             const gchar              *cookie,
                                             PolkitIdentity           *identity,
                                             GError                  **error);

  GList *(*enumerate_temporary_authorizations) (PolkitBackendAuthority   *authority,
                                                PolkitSubject            *caller,
                                                PolkitSubject            *subject,
                                                GError                  **error);

  gboolean (*revoke_temporary_authorizations) (PolkitBackendAuthority   *authority,
                                               PolkitSubject            *caller,
                                               PolkitSubject            *subject,
                                               GError                  **error);

  gboolean (*revoke_temporary_authorization_by_id) (PolkitBackendAuthority   *authority,
                                                    PolkitSubject            *caller,
                                                    const gchar              *id,
                                                    GError                  **error);

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
  void (*_polkit_reserved9) (void);
  void (*_polkit_reserved10) (void);
  void (*_polkit_reserved11) (void);
  void (*_polkit_reserved12) (void);
  void (*_polkit_reserved13) (void);
  void (*_polkit_reserved14) (void);
  void (*_polkit_reserved15) (void);
  void (*_polkit_reserved16) (void);
  void (*_polkit_reserved17) (void);
  void (*_polkit_reserved18) (void);
  void (*_polkit_reserved19) (void);
  void (*_polkit_reserved20) (void);
  void (*_polkit_reserved21) (void);
  void (*_polkit_reserved22) (void);
  void (*_polkit_reserved23) (void);
  void (*_polkit_reserved24) (void);
  void (*_polkit_reserved25) (void);
  void (*_polkit_reserved26) (void);
  void (*_polkit_reserved27) (void);
  void (*_polkit_reserved28) (void);
  void (*_polkit_reserved29) (void);
  void (*_polkit_reserved30) (void);
  void (*_polkit_reserved31) (void);
  void (*_polkit_reserved32) (void);
};

GType    polkit_backend_authority_get_type (void) G_GNUC_CONST;

/* --- */

const gchar             *polkit_backend_authority_get_name     (PolkitBackendAuthority *authority);
const gchar             *polkit_backend_authority_get_version  (PolkitBackendAuthority *authority);
PolkitAuthorityFeatures  polkit_backend_authority_get_features (PolkitBackendAuthority *authority);

void     polkit_backend_authority_log (PolkitBackendAuthority *authority,
                                       const gchar *format,
                                       ...);

GList   *polkit_backend_authority_enumerate_actions         (PolkitBackendAuthority    *authority,
                                                             PolkitSubject             *caller,
                                                             const gchar               *locale,
                                                             GError                   **error);

void     polkit_backend_authority_check_authorization       (PolkitBackendAuthority        *authority,
                                                             PolkitSubject                 *caller,
                                                             PolkitSubject                 *subject,
                                                             const gchar                   *action_id,
                                                             PolkitDetails                 *details,
                                                             PolkitCheckAuthorizationFlags  flags,
                                                             GCancellable                  *cancellable,
                                                             GAsyncReadyCallback            callback,
                                                             gpointer                       user_data);

PolkitAuthorizationResult *polkit_backend_authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                                                                GAsyncResult            *res,
                                                                                GError                 **error);

gboolean polkit_backend_authority_register_authentication_agent (PolkitBackendAuthority    *authority,
                                                                 PolkitSubject             *caller,
                                                                 PolkitSubject             *subject,
                                                                 const gchar               *locale,
                                                                 const gchar               *object_path,
                                                                 GVariant                  *options,
                                                                 GError                   **error);

gboolean polkit_backend_authority_unregister_authentication_agent (PolkitBackendAuthority    *authority,
                                                                   PolkitSubject             *caller,
                                                                   PolkitSubject             *subject,
                                                                   const gchar               *object_path,
                                                                   GError                   **error);

gboolean polkit_backend_authority_authentication_agent_response (PolkitBackendAuthority    *authority,
                                                                 PolkitSubject             *caller,
                                                                 uid_t                      uid,
                                                                 const gchar               *cookie,
                                                                 PolkitIdentity            *identity,
                                                                 GError                   **error);

GList *polkit_backend_authority_enumerate_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                                    PolkitSubject            *caller,
                                                                    PolkitSubject            *subject,
                                                                    GError                  **error);

gboolean polkit_backend_authority_revoke_temporary_authorizations (PolkitBackendAuthority   *authority,
                                                                   PolkitSubject            *caller,
                                                                   PolkitSubject            *subject,
                                                                   GError                  **error);

gboolean polkit_backend_authority_revoke_temporary_authorization_by_id (PolkitBackendAuthority   *authority,
                                                                        PolkitSubject            *caller,
                                                                        const gchar              *id,
                                                                        GError                  **error);

/* --- */

PolkitBackendAuthority *polkit_backend_authority_get (void);

gpointer polkit_backend_authority_register (PolkitBackendAuthority   *authority,
                                            GDBusConnection          *connection,
                                            const gchar              *object_path,
                                            GError                  **error);

void polkit_backend_authority_unregister (gpointer registration_id);

G_END_DECLS

#endif /* __POLKIT_BACKEND_AUTHORITY_H */

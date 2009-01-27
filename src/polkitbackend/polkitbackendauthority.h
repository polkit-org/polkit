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

struct _PolkitBackendAuthority
{
  GObject parent_instance;
};

struct _PolkitBackendAuthorityClass
{
  GObjectClass parent_class;

  /*< public >*/

  /* Signals */
  void (*changed)  (PolkitBackendAuthority   *authority);

  /* VTable */

  /* TODO: need something more efficient such that we don't watch all name changes */
  void (*system_bus_name_owner_changed)  (PolkitBackendAuthority   *authority,
                                          const gchar              *name,
                                          const gchar              *old_owner,
                                          const gchar              *new_owner);

  void (*enumerate_actions)  (PolkitBackendAuthority   *authority,
                              const gchar              *locale,
                              PolkitBackendPendingCall *pending_call);

  void (*enumerate_users)    (PolkitBackendAuthority   *authority,
                              PolkitBackendPendingCall *pending_call);

  void (*enumerate_groups)   (PolkitBackendAuthority   *authority,
                              PolkitBackendPendingCall *pending_call);

  void (*check_authorization) (PolkitBackendAuthority        *authority,
                               PolkitSubject                 *subject,
                               const gchar                   *action_id,
                               PolkitCheckAuthorizationFlags  flags,
                               PolkitBackendPendingCall      *pending_call);

  void (*enumerate_authorizations) (PolkitBackendAuthority   *authority,
                                    PolkitIdentity           *identity,
                                    PolkitBackendPendingCall *pending_call);

  void (*add_authorization) (PolkitBackendAuthority   *authority,
                             PolkitIdentity           *identity,
                             PolkitAuthorization      *authorization,
                             PolkitBackendPendingCall *pending_call);

  void (*remove_authorization) (PolkitBackendAuthority   *authority,
                                PolkitIdentity           *identity,
                                PolkitAuthorization      *authorization,
                                PolkitBackendPendingCall *pending_call);

  void (*register_authentication_agent) (PolkitBackendAuthority   *authority,
                                         const gchar              *object_path,
                                         PolkitBackendPendingCall *pending_call);

  void (*unregister_authentication_agent) (PolkitBackendAuthority   *authority,
                                           const gchar              *object_path,
                                           PolkitBackendPendingCall *pending_call);

  void (*authentication_agent_response) (PolkitBackendAuthority   *authority,
                                         const gchar              *cookie,
                                         PolkitIdentity           *identity,
                                         PolkitBackendPendingCall *pending_call);

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

void     polkit_backend_authority_enumerate_actions         (PolkitBackendAuthority    *authority,
                                                             const gchar               *locale,
                                                             PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_enumerate_users           (PolkitBackendAuthority    *authority,
                                                             PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_enumerate_groups          (PolkitBackendAuthority    *authority,
                                                             PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_check_authorization       (PolkitBackendAuthority        *authority,
                                                             PolkitSubject                 *subject,
                                                             const gchar                   *action_id,
                                                             PolkitCheckAuthorizationFlags  flags,
                                                             PolkitBackendPendingCall      *pending_call);

void     polkit_backend_authority_enumerate_authorizations  (PolkitBackendAuthority    *authority,
                                                             PolkitIdentity            *identity,
                                                             PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_add_authorization         (PolkitBackendAuthority    *authority,
                                                             PolkitIdentity            *identity,
                                                             PolkitAuthorization       *authorization,
                                                             PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_remove_authorization      (PolkitBackendAuthority    *authority,
                                                             PolkitIdentity            *identity,
                                                             PolkitAuthorization       *authorization,
                                                             PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_register_authentication_agent (PolkitBackendAuthority    *authority,
                                                                 const gchar               *object_path,
                                                                 PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_unregister_authentication_agent (PolkitBackendAuthority    *authority,
                                                                   const gchar               *object_path,
                                                                   PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_authentication_agent_response (PolkitBackendAuthority    *authority,
                                                                 const gchar               *cookie,
                                                                 PolkitIdentity            *identity,
                                                                 PolkitBackendPendingCall  *pending_call);

/* --- */

void     polkit_backend_authority_enumerate_actions_finish        (PolkitBackendPendingCall  *pending_call,
                                                                   GList                     *actions);

void     polkit_backend_authority_enumerate_users_finish          (PolkitBackendPendingCall  *pending_call,
                                                                   GList                     *users);

void     polkit_backend_authority_enumerate_groups_finish         (PolkitBackendPendingCall  *pending_call,
                                                                   GList                     *groups);

void     polkit_backend_authority_check_authorization_finish      (PolkitBackendPendingCall  *pending_call,
                                                                   PolkitAuthorizationResult  result);

void     polkit_backend_authority_enumerate_authorizations_finish (PolkitBackendPendingCall  *pending_call,
                                                                   GList                     *authorizations);

void     polkit_backend_authority_add_authorization_finish        (PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_remove_authorization_finish     (PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_register_authentication_agent_finish   (PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_unregister_authentication_agent_finish (PolkitBackendPendingCall  *pending_call);

void     polkit_backend_authority_authentication_agent_response_finish (PolkitBackendPendingCall  *pending_call);


G_END_DECLS

#endif /* __POLKIT_BACKEND_AUTHORITY_H */


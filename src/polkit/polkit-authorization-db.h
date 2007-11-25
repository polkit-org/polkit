/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-db.h : Represents the authorization database
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_AUTHORIZATION_DB_H
#define POLKIT_AUTHORIZATION_DB_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-authorization.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-error.h>

POLKIT_BEGIN_DECLS

struct _PolKitAuthorizationDB;
typedef struct _PolKitAuthorizationDB PolKitAuthorizationDB;

/**
 * PolKitAuthorizationDBCapability:
 * @POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN: Users can obtain
 * authorizations through authentication
 *
 * Capabilities of the authorization database backend.
 *
 * Since: 0.7
 */
typedef enum
{
        POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN = 1 << 0
} PolKitAuthorizationDBCapability;

PolKitAuthorizationDBCapability polkit_authorization_db_get_capabilities (void);

PolKitAuthorizationDB *polkit_authorization_db_ref            (PolKitAuthorizationDB *authdb);
void                   polkit_authorization_db_unref          (PolKitAuthorizationDB *authdb);

void                   polkit_authorization_db_debug          (PolKitAuthorizationDB *authdb);
polkit_bool_t          polkit_authorization_db_validate       (PolKitAuthorizationDB *authdb);

polkit_bool_t polkit_authorization_db_is_session_authorized (PolKitAuthorizationDB *authdb,
                                                             PolKitAction          *action,
                                                             PolKitSession         *session,
                                                             polkit_bool_t         *out_is_authorized,
                                                             polkit_bool_t         *out_is_negative_authorized,
                                                             PolKitError          **error);

polkit_bool_t polkit_authorization_db_is_caller_authorized (PolKitAuthorizationDB *authdb,
                                                            PolKitAction          *action,
                                                            PolKitCaller          *caller,
                                                            polkit_bool_t          revoke_if_one_shot,
                                                            polkit_bool_t         *out_is_authorized,
                                                            polkit_bool_t         *out_is_negative_authorized,
                                                            PolKitError          **error);

/**
 * PolKitAuthorizationDBForeach:
 * @authdb: authorization database
 * @auth: authorization; user shall not unref this object. Unless
 * reffed by the user it will be destroyed when the callback function
 * returns.
 * @user_data: user data passed
 *
 * Type of callback function for iterating over authorizations.
 *
 * Returns: pass #TRUE to stop iterating
 *
 * Since: 0.7
 */
typedef polkit_bool_t (*PolKitAuthorizationDBForeach) (PolKitAuthorizationDB *authdb,
                                                       PolKitAuthorization   *auth, 
                                                       void                  *user_data);

polkit_bool_t polkit_authorization_db_foreach (PolKitAuthorizationDB       *authdb,
                                               PolKitAuthorizationDBForeach cb,
                                               void                        *user_data,
                                               PolKitError                **error);

polkit_bool_t polkit_authorization_db_foreach_for_uid (PolKitAuthorizationDB       *authdb,
                                                       uid_t                        uid,
                                                       PolKitAuthorizationDBForeach cb,
                                                       void                        *user_data,
                                                       PolKitError                **error);

polkit_bool_t polkit_authorization_db_foreach_for_action (PolKitAuthorizationDB       *authdb,
                                                          PolKitAction                *action,
                                                          PolKitAuthorizationDBForeach cb,
                                                          void                        *user_data,
                                                          PolKitError                **error);

polkit_bool_t polkit_authorization_db_foreach_for_action_for_uid (PolKitAuthorizationDB       *authdb,
                                                                  PolKitAction                *action,
                                                                  uid_t                        uid,
                                                                  PolKitAuthorizationDBForeach cb,
                                                                  void                        *user_data,
                                                                  PolKitError                **error);

polkit_bool_t polkit_authorization_db_add_entry_process_one_shot (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  PolKitCaller          *caller,
                                                                  uid_t                  user_authenticated_as);

polkit_bool_t polkit_authorization_db_add_entry_process          (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  PolKitCaller          *caller,
                                                                  uid_t                  user_authenticated_as);

polkit_bool_t polkit_authorization_db_add_entry_session          (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  PolKitCaller          *caller,
                                                                  uid_t                  user_authenticated_as);

polkit_bool_t polkit_authorization_db_add_entry_always           (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  PolKitCaller          *caller,
                                                                  uid_t                  user_authenticated_as);

polkit_bool_t polkit_authorization_db_grant_to_uid           (PolKitAuthorizationDB          *authdb,
                                                              PolKitAction                   *action,
                                                              uid_t                           uid,
                                                              PolKitAuthorizationConstraint  *constraint,
                                                              PolKitError                   **error);

polkit_bool_t polkit_authorization_db_grant_negative_to_uid           (PolKitAuthorizationDB          *authdb,
                                                                       PolKitAction                   *action,
                                                                       uid_t                           uid,
                                                                       PolKitAuthorizationConstraint  *constraint,
                                                                       PolKitError                   **error);

polkit_bool_t polkit_authorization_db_revoke_entry (PolKitAuthorizationDB *authdb,
                                                    PolKitAuthorization *auth,
                                                    PolKitError **error);


polkit_bool_t polkit_authorization_db_is_uid_blocked_by_self (PolKitAuthorizationDB *authdb,
                                                              PolKitAction          *action,
                                                              uid_t                  uid,
                                                              PolKitError          **error);

POLKIT_END_DECLS

#endif /* POLKIT_AUTHORIZATION_DB_H */



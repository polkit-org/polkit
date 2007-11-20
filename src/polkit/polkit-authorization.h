/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization.h : Represents an entry in the authorization
 * database
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

#ifndef POLKIT_AUTHORIZATION_H
#define POLKIT_AUTHORIZATION_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-authorization-constraint.h>

POLKIT_BEGIN_DECLS

struct _PolKitAuthorization;
typedef struct _PolKitAuthorization PolKitAuthorization;

PolKitAuthorization *polkit_authorization_ref            (PolKitAuthorization *auth);
void                 polkit_authorization_unref          (PolKitAuthorization *auth);

void                 polkit_authorization_debug          (PolKitAuthorization *auth);
polkit_bool_t        polkit_authorization_validate       (PolKitAuthorization *auth);


/**
 * PolKitAuthorizationScope:
 * @POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT: The authorization is
 * limited for a single shot for a single process on the system
 * @POLKIT_AUTHORIZATION_SCOPE_PROCESS: The authorization is limited
 * for a single process on the system
 * @POLKIT_AUTHORIZATION_SCOPE_SESSION: The authorization is limited
 * for processes originating from a given session
 * @POLKIT_AUTHORIZATION_SCOPE_ALWAYS: The authorization is retained
 * indefinitely.
 *
 * The scope of an authorization; e.g. whether it's limited to a
 * process, a session or unlimited.
 */
typedef enum {
        POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT,
        POLKIT_AUTHORIZATION_SCOPE_PROCESS,
        POLKIT_AUTHORIZATION_SCOPE_SESSION,
        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
} PolKitAuthorizationScope;

const char *polkit_authorization_get_action_id (PolKitAuthorization *auth);

uid_t polkit_authorization_get_uid (PolKitAuthorization *auth);

time_t polkit_authorization_get_time_of_grant            (PolKitAuthorization *auth);

PolKitAuthorizationConstraint *polkit_authorization_get_constraint (PolKitAuthorization *auth);

PolKitAuthorizationScope polkit_authorization_get_scope (PolKitAuthorization *auth);


polkit_bool_t polkit_authorization_scope_process_get_pid        (PolKitAuthorization *auth, 
                                                                 pid_t *out_pid, 
                                                                 polkit_uint64_t *out_pid_start_time);

const char *polkit_authorization_scope_session_get_ck_objref  (PolKitAuthorization *auth);


polkit_bool_t polkit_authorization_was_granted_via_defaults  (PolKitAuthorization *auth,
                                                              uid_t *out_user_authenticated_as);

polkit_bool_t polkit_authorization_was_granted_explicitly  (PolKitAuthorization *auth,
                                                            uid_t *out_by_whom,
                                                            polkit_bool_t *out_is_negative);

POLKIT_END_DECLS

#endif /* POLKIT_AUTHORIZATION_H */



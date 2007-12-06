/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization.h : Represents an entry in the authorization
 * database
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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
 *
 * Since: 0.7
 */
typedef enum {
        POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT,
        POLKIT_AUTHORIZATION_SCOPE_PROCESS,
        POLKIT_AUTHORIZATION_SCOPE_SESSION,
        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
} PolKitAuthorizationScope;

/**
 * PolKitAuthorizationType:
 * @POLKIT_AUTHORIZATION_TYPE_UID: The authorization is for a UNIX user
 *
 * The type of authorization; e.g. whether it applies to a user,
 * group, security context and so on (right now only users are
 * supported).
 *
 * Since: 0.7
 */
typedef enum {
        POLKIT_AUTHORIZATION_TYPE_UID,
} PolKitAuthorizationType;

PolKitAuthorizationType polkit_authorization_type (PolKitAuthorization *auth);

const char *polkit_authorization_get_action_id (PolKitAuthorization *auth);

uid_t polkit_authorization_get_uid (PolKitAuthorization *auth);

time_t polkit_authorization_get_time_of_grant            (PolKitAuthorization *auth);

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

/**
 * PolKitAuthorizationConstraintsForeachFunc:
 * @auth: authorization
 * @authc: authorization constraint
 * @user_data: user data 
 *
 * Callback function for polkit_authorization_constraints_foreach().
 *
 * Returns: Pass #TRUE to short-circuit, e.g. stop the iteration
 */
typedef polkit_bool_t (*PolKitAuthorizationConstraintsForeachFunc) (PolKitAuthorization *auth,
                                                                    PolKitAuthorizationConstraint *authc,
                                                                    void *user_data);

polkit_bool_t
polkit_authorization_constraints_foreach (PolKitAuthorization *auth, 
                                          PolKitAuthorizationConstraintsForeachFunc cb, 
                                          void *user_data);

POLKIT_END_DECLS

#endif /* POLKIT_AUTHORIZATION_H */



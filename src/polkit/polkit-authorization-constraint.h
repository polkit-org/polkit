/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-constraint.h : Conditions that must be
 * satisfied in order for an authorization to apply
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

#ifndef POLKIT_AUTHORIZATION_CONSTRAINT_H
#define POLKIT_AUTHORIZATION_CONSTRAINT_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>

POLKIT_BEGIN_DECLS

/**
 * PolKitAuthorizationConstraintType:
 * @POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL: the session or
 * caller must be local
 * @POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE: the session or
 * caller must be in an active session
 * @POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE: the caller must
 * be a specific program; use
 * polkit_authorization_constraint_get_exe() to get the path of the
 * program.
 * @POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT: the
 * caller must be in a specific security context
 * polkit_authorization_constraint_get_selinux_context() to get the
 * security context.
 *
 * This enumeration describes the type of the authorization
 * constraint.
 */
typedef enum {
        POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL,
        POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE,
        POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE,
        POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT,
} PolKitAuthorizationConstraintType;

struct _PolKitAuthorizationConstraint;
typedef struct _PolKitAuthorizationConstraint PolKitAuthorizationConstraint;

PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_local (void);
PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_active (void);
PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_exe (const char *path);
PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_selinux_context (const char *context);

PolKitAuthorizationConstraint *polkit_authorization_constraint_ref      (PolKitAuthorizationConstraint *authc);
void                           polkit_authorization_constraint_unref    (PolKitAuthorizationConstraint *authc);
void                           polkit_authorization_constraint_debug    (PolKitAuthorizationConstraint *authc);
polkit_bool_t                  polkit_authorization_constraint_validate (PolKitAuthorizationConstraint *authc);

PolKitAuthorizationConstraintType polkit_authorization_constraint_type (PolKitAuthorizationConstraint *authc);

const char *polkit_authorization_constraint_get_exe (PolKitAuthorizationConstraint *authc);

const char *polkit_authorization_constraint_get_selinux_context (PolKitAuthorizationConstraint *authc);

polkit_bool_t polkit_authorization_constraint_check_session (PolKitAuthorizationConstraint *authc,
                                                             PolKitSession                 *session);

polkit_bool_t polkit_authorization_constraint_check_caller (PolKitAuthorizationConstraint *authc,
                                                            PolKitCaller                  *caller);

size_t                         polkit_authorization_constraint_to_string (PolKitAuthorizationConstraint *authc, char *out_buf, size_t buf_size);
PolKitAuthorizationConstraint *polkit_authorization_constraint_from_string (const char *str);

int polkit_authorization_constraint_get_from_caller (PolKitCaller *caller, PolKitAuthorizationConstraint **out_array, size_t array_size);

polkit_bool_t                  polkit_authorization_constraint_equal (PolKitAuthorizationConstraint *a,
                                                                      PolKitAuthorizationConstraint *b);

POLKIT_END_DECLS

#endif /* POLKIT_AUTHORIZATION_CONSTRAINT_H */



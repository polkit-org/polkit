/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-constraint.h : Conditions that must be
 * satisfied in order for an authorization to apply
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

#ifndef POLKIT_AUTHORIZATION_CONSTRAINT_H
#define POLKIT_AUTHORIZATION_CONSTRAINT_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>

POLKIT_BEGIN_DECLS

/**
 * PolKitAuthorizationConstraintFlags:
 * @POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL: the session or
 * caller must be local
 * @POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE: the session or
 * caller must be in an active session
 * @POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL_ACTIVE: short
 * hand for the flags POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL
 * and POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE.
 *
 * This enumeration describes different conditions, not mutually
 * exclusive, to help describe an authorization constraint.
 */
typedef enum {
        POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL         = 1 << 0,
        POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE        = 1 << 1,
        POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL_ACTIVE  = (1 << 0) | (1 << 1)
} PolKitAuthorizationConstraintFlags;

struct _PolKitAuthorizationConstraint;
typedef struct _PolKitAuthorizationConstraint PolKitAuthorizationConstraint;

PolKitAuthorizationConstraint *polkit_authorization_constraint_get_null (void);
PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_local (void);
PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_active (void);
PolKitAuthorizationConstraint *polkit_authorization_constraint_get_require_local_active (void);

PolKitAuthorizationConstraint *polkit_authorization_constraint_ref      (PolKitAuthorizationConstraint *authc);
void                           polkit_authorization_constraint_unref    (PolKitAuthorizationConstraint *authc);
void                           polkit_authorization_constraint_debug    (PolKitAuthorizationConstraint *authc);
polkit_bool_t                  polkit_authorization_constraint_validate (PolKitAuthorizationConstraint *authc);

PolKitAuthorizationConstraintFlags polkit_authorization_constraint_get_flags (PolKitAuthorizationConstraint *authc);

polkit_bool_t polkit_authorization_constraint_check_session (PolKitAuthorizationConstraint *authc,
                                                             PolKitSession                 *session);

polkit_bool_t polkit_authorization_constraint_check_caller (PolKitAuthorizationConstraint *authc,
                                                            PolKitCaller                  *caller);

size_t                         polkit_authorization_constraint_to_string (PolKitAuthorizationConstraint *authc, char *out_buf, size_t buf_size);
PolKitAuthorizationConstraint *polkit_authorization_constraint_from_string (const char *str);

PolKitAuthorizationConstraint *polkit_authorization_constraint_get_from_caller (PolKitCaller *caller);

polkit_bool_t                  polkit_authorization_constraint_equal (PolKitAuthorizationConstraint *a,
                                                                      PolKitAuthorizationConstraint *b);

POLKIT_END_DECLS

#endif /* POLKIT_AUTHORIZATION_CONSTRAINT_H */



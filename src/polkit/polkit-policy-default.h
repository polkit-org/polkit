/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-default.h : policy definition for the defaults
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

#ifndef POLKIT_POLICY_DEFAULT_H
#define POLKIT_POLICY_DEFAULT_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-error.h>

POLKIT_BEGIN_DECLS

struct _PolKitPolicyDefault;
typedef struct _PolKitPolicyDefault PolKitPolicyDefault;

PolKitPolicyDefault    *polkit_policy_default_ref   (PolKitPolicyDefault *policy_default);
void                    polkit_policy_default_unref (PolKitPolicyDefault *policy_default);
void                    polkit_policy_default_debug (PolKitPolicyDefault *policy_default);

PolKitResult polkit_policy_default_can_session_do_action (PolKitPolicyDefault *policy_default,
                                                          PolKitAction        *action,
                                                          PolKitSession       *session);

PolKitResult polkit_policy_default_can_caller_do_action (PolKitPolicyDefault *policy_default,
                                                         PolKitAction        *action,
                                                         PolKitCaller        *caller);

PolKitResult polkit_policy_default_get_allow_any (PolKitPolicyDefault *policy_default);
PolKitResult polkit_policy_default_get_allow_inactive (PolKitPolicyDefault *policy_default);
PolKitResult polkit_policy_default_get_allow_active (PolKitPolicyDefault *policy_default);

/* TODO: export knobs for "default policy" */

POLKIT_END_DECLS

#endif /* POLKIT_POLICY_DEFAULT_H */



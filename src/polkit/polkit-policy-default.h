/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-default.h : policy definition for the defaults
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

PolKitPolicyDefault    *polkit_policy_default_new   (void);
PolKitPolicyDefault    *polkit_policy_default_ref   (PolKitPolicyDefault *policy_default);
void                    polkit_policy_default_unref (PolKitPolicyDefault *policy_default);
void                    polkit_policy_default_debug (PolKitPolicyDefault *policy_default);
PolKitPolicyDefault    *polkit_policy_default_clone (PolKitPolicyDefault *policy_default);

polkit_bool_t           polkit_policy_default_equals (PolKitPolicyDefault *a, PolKitPolicyDefault *b);

PolKitResult polkit_policy_default_can_session_do_action (PolKitPolicyDefault *policy_default,
                                                          PolKitAction        *action,
                                                          PolKitSession       *session);

PolKitResult polkit_policy_default_can_caller_do_action (PolKitPolicyDefault *policy_default,
                                                         PolKitAction        *action,
                                                         PolKitCaller        *caller);

PolKitResult polkit_policy_default_get_allow_any      (PolKitPolicyDefault *policy_default);
PolKitResult polkit_policy_default_get_allow_inactive (PolKitPolicyDefault *policy_default);
PolKitResult polkit_policy_default_get_allow_active   (PolKitPolicyDefault *policy_default);

void         polkit_policy_default_set_allow_any      (PolKitPolicyDefault *policy_default, PolKitResult value);
void         polkit_policy_default_set_allow_inactive (PolKitPolicyDefault *policy_default, PolKitResult value);
void         polkit_policy_default_set_allow_active   (PolKitPolicyDefault *policy_default, PolKitResult value);


/* TODO: export knobs for "default policy" */

POLKIT_END_DECLS

#endif /* POLKIT_POLICY_DEFAULT_H */



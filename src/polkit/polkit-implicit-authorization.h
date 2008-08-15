/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-implicit-authorization.h : policy definition for the defaults
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

#ifndef POLKIT_IMPLICIT_AUTHORIZATION_H
#define POLKIT_IMPLICIT_AUTHORIZATION_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-error.h>

POLKIT_BEGIN_DECLS

struct _PolKitImplicitAuthorization;
typedef struct _PolKitImplicitAuthorization PolKitImplicitAuthorization;

PolKitImplicitAuthorization    *polkit_implicit_authorization_new   (void);
PolKitImplicitAuthorization    *polkit_implicit_authorization_ref   (PolKitImplicitAuthorization *implicit_authorization);
void                    polkit_implicit_authorization_unref (PolKitImplicitAuthorization *implicit_authorization);
void                    polkit_implicit_authorization_debug (PolKitImplicitAuthorization *implicit_authorization);
PolKitImplicitAuthorization    *polkit_implicit_authorization_clone (PolKitImplicitAuthorization *implicit_authorization);

polkit_bool_t           polkit_implicit_authorization_equals (PolKitImplicitAuthorization *a, PolKitImplicitAuthorization *b);

PolKitResult polkit_implicit_authorization_can_session_do_action (PolKitImplicitAuthorization *implicit_authorization,
                                                          PolKitAction        *action,
                                                          PolKitSession       *session);

PolKitResult polkit_implicit_authorization_can_caller_do_action (PolKitImplicitAuthorization *implicit_authorization,
                                                         PolKitAction        *action,
                                                         PolKitCaller        *caller);

PolKitResult polkit_implicit_authorization_get_allow_any      (PolKitImplicitAuthorization *implicit_authorization);
PolKitResult polkit_implicit_authorization_get_allow_inactive (PolKitImplicitAuthorization *implicit_authorization);
PolKitResult polkit_implicit_authorization_get_allow_active   (PolKitImplicitAuthorization *implicit_authorization);

void         polkit_implicit_authorization_set_allow_any      (PolKitImplicitAuthorization *implicit_authorization, PolKitResult value);
void         polkit_implicit_authorization_set_allow_inactive (PolKitImplicitAuthorization *implicit_authorization, PolKitResult value);
void         polkit_implicit_authorization_set_allow_active   (PolKitImplicitAuthorization *implicit_authorization, PolKitResult value);


/* TODO: export knobs for "default policy" */

POLKIT_END_DECLS

#endif /* POLKIT_IMPLICIT_AUTHORIZATION_H */



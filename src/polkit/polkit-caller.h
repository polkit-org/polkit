/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-caller.h : callers
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

#ifndef POLKIT_CALLER_H
#define POLKIT_CALLER_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-session.h>
#include <sys/types.h>

POLKIT_BEGIN_DECLS

struct _PolKitCaller;
typedef struct _PolKitCaller PolKitCaller;

PolKitCaller     *polkit_caller_new                 (void);
PolKitCaller     *polkit_caller_ref                 (PolKitCaller   *caller);
void              polkit_caller_unref               (PolKitCaller   *caller);
polkit_bool_t     polkit_caller_set_dbus_name       (PolKitCaller   *caller, const char     *dbus_name);
polkit_bool_t     polkit_caller_set_uid             (PolKitCaller   *caller, uid_t           uid);
polkit_bool_t     polkit_caller_set_pid             (PolKitCaller   *caller, pid_t           pid);
polkit_bool_t     polkit_caller_set_selinux_context (PolKitCaller   *caller, const char     *selinux_context);
polkit_bool_t     polkit_caller_set_ck_session      (PolKitCaller   *caller, PolKitSession  *session);
polkit_bool_t     polkit_caller_get_dbus_name       (PolKitCaller   *caller, char          **out_dbus_name);
polkit_bool_t     polkit_caller_get_uid             (PolKitCaller   *caller, uid_t          *out_uid);
polkit_bool_t     polkit_caller_get_pid             (PolKitCaller   *caller, pid_t          *out_pid);
polkit_bool_t     polkit_caller_get_selinux_context (PolKitCaller   *caller, char          **out_selinux_context);
polkit_bool_t     polkit_caller_get_ck_session      (PolKitCaller   *caller, PolKitSession **out_session);

void              polkit_caller_debug               (PolKitCaller   *caller);
polkit_bool_t     polkit_caller_validate            (PolKitCaller   *caller);

POLKIT_END_DECLS

#endif /* POLKIT_H */

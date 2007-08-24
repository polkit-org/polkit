/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-caller.h : callers
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

#ifndef POLKIT_CALLER_H
#define POLKIT_CALLER_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-session.h>
#include <sys/types.h>

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

#endif /* POLKIT_H */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-caller.h : callers
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

#ifndef LIBPOLKIT_CALLER_H
#define LIBPOLKIT_CALLER_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-session.h>

struct PolKitCaller_s;
typedef struct PolKitCaller_s PolKitCaller;

PolKitCaller     *libpolkit_caller_new                 (void);
PolKitCaller     *libpolkit_caller_ref                 (PolKitCaller *caller);
void              libpolkit_caller_set_dbus_name       (PolKitCaller *caller, const char *dbus_name);
void              libpolkit_caller_set_uid             (PolKitCaller *caller, uid_t       uid);
void              libpolkit_caller_set_pid             (PolKitCaller *caller, pid_t       pid);
void              libpolkit_caller_set_selinux_context (PolKitCaller *caller, const char *selinux_context);
void              libpolkit_caller_set_ck_session      (PolKitCaller *caller, PolKitSession  *session);
gboolean          libpolkit_caller_get_dbus_name       (PolKitCaller *caller, char      **out_dbus_name);
gboolean          libpolkit_caller_get_uid             (PolKitCaller *caller, uid_t      *out_uid);
gboolean          libpolkit_caller_get_pid             (PolKitCaller *caller, uid_t      *out_pid);
gboolean          libpolkit_caller_get_selinux_context (PolKitCaller *caller, char       *out_selinux_context);
gboolean          libpolkit_caller_get_ck_session      (PolKitCaller *caller, PolKitSession **out_session);
void              libpolkit_caller_unref               (PolKitCaller *caller);

#endif /* LIBPOLKIT_H */



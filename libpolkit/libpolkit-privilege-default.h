/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege-default.h : privilege definition for the defaults
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

#ifndef LIBPOLKIT_PRIVILEGE_DEFAULT_H
#define LIBPOLKIT_PRIVILEGE_DEFAULT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-result.h>
#include <libpolkit/libpolkit-privilege.h>
#include <libpolkit/libpolkit-resource.h>
#include <libpolkit/libpolkit-session.h>
#include <libpolkit/libpolkit-caller.h>

struct PolKitPrivilegeDefault;
typedef struct PolKitPrivilegeDefault PolKitPrivilegeDefault;

PolKitPrivilegeDefault *libpolkit_privilege_default_new   (GKeyFile *key_file, const char *privilege, GError **error);
PolKitPrivilegeDefault *libpolkit_privilege_default_ref   (PolKitPrivilegeDefault *privilege_default);
void                    libpolkit_privilege_default_unref (PolKitPrivilegeDefault *privilege_default);
void                    libpolkit_privilege_default_debug (PolKitPrivilegeDefault *privilege_default);

PolKitResult libpolkit_privilege_default_can_session_access_resource (PolKitPrivilegeDefault *privilege_default,
                                                                      PolKitPrivilege        *privilege,
                                                                      PolKitResource         *resource,
                                                                      PolKitSession          *session);
PolKitResult libpolkit_privilege_default_can_caller_access_resource (PolKitPrivilegeDefault *privilege_default,
                                                                     PolKitPrivilege        *privilege,
                                                                     PolKitResource         *resource,
                                                                     PolKitCaller           *caller);

/* TODO: export knobs for "default policy" */

#endif /* LIBPOLKIT_PRIVILEGE_DEFAULT_H */



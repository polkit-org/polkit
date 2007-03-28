/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege.h : privileges
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

#ifndef LIBPOLKIT_PRIVILEGE_H
#define LIBPOLKIT_PRIVILEGE_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

struct PolKitPrivilege_s;
typedef struct PolKitPrivilege_s PolKitPrivilege;

PolKitPrivilege *libpolkit_privilege_new              (void);
PolKitPrivilege *libpolkit_privilege_ref              (PolKitPrivilege *privilege);
void             libpolkit_privilege_set_privilege_id (PolKitPrivilege *privilege, const char  *privilege_id);
gboolean         libpolkit_privilege_get_privilege_id (PolKitPrivilege *privilege, char       **out_privilege_id);
void             libpolkit_privilege_unref            (PolKitPrivilege *privilege);

#endif /* LIBPOLKIT_PRIVILEGE_H */



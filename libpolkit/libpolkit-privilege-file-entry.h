/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege-file-entry.h : entries in privilege files
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

#ifndef LIBPOLKIT_PRIVILEGE_FILE_ENTRY_H
#define LIBPOLKIT_PRIVILEGE_FILE_ENTRY_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-result.h>
#include <libpolkit/libpolkit-privilege-default.h>

struct PolKitPrivilegeFileEntry;
typedef struct PolKitPrivilegeFileEntry PolKitPrivilegeFileEntry;

PolKitPrivilegeFileEntry *libpolkit_privilege_file_entry_new   (GKeyFile *key_file, const char *privilege, GError **error);
PolKitPrivilegeFileEntry *libpolkit_privilege_file_entry_ref   (PolKitPrivilegeFileEntry *privilege_file_entry);
void                      libpolkit_privilege_file_entry_unref (PolKitPrivilegeFileEntry *privilege_file_entry);
void                      libpolkit_privilege_file_entry_debug (PolKitPrivilegeFileEntry *privilege_file_entry);

const char             *libpolkit_privilege_file_entry_get_id      (PolKitPrivilegeFileEntry *privilege_file_entry);
PolKitPrivilegeDefault *libpolkit_privilege_file_entry_get_default (PolKitPrivilegeFileEntry *privilege_file_entry);


#endif /* LIBPOLKIT_PRIVILEGE_FILE_ENTRY_H */



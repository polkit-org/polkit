/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege-cache.h : privilege cache
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

#ifndef LIBPOLKIT_PRIVILEGE_CACHE_H
#define LIBPOLKIT_PRIVILEGE_CACHE_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-privilege.h>
#include <libpolkit/libpolkit-privilege-file-entry.h>

struct PolKitPrivilegeCache;
typedef struct PolKitPrivilegeCache PolKitPrivilegeCache;

PolKitPrivilegeCache *libpolkit_privilege_cache_new                   (const char *dirname, GError **error);
PolKitPrivilegeCache *libpolkit_privilege_cache_ref                   (PolKitPrivilegeCache *privilege_cache);
void                  libpolkit_privilege_cache_unref                 (PolKitPrivilegeCache *privilege_cache);
void                  libpolkit_privilege_cache_debug                 (PolKitPrivilegeCache *privilege_cache);

PolKitPrivilegeFileEntry* libpolkit_privilege_cache_get_entry (PolKitPrivilegeCache *privilege_cache,
                                                               PolKitPrivilege      *privilege);

#endif /* LIBPOLKIT_PRIVILEGE_CACHE_H */



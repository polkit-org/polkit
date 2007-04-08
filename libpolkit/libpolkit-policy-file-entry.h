/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-file-entry.h : entries in policy files
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

#ifndef LIBPOLKIT_POLICY_FILE_ENTRY_H
#define LIBPOLKIT_POLICY_FILE_ENTRY_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-result.h>
#include <libpolkit/libpolkit-policy-default.h>

struct PolKitPolicyFileEntry;
typedef struct PolKitPolicyFileEntry PolKitPolicyFileEntry;

PolKitPolicyFileEntry *libpolkit_policy_file_entry_new   (GKeyFile *key_file, const char *action, GError **error);
PolKitPolicyFileEntry *libpolkit_policy_file_entry_ref   (PolKitPolicyFileEntry *policy_file_entry);
void                   libpolkit_policy_file_entry_unref (PolKitPolicyFileEntry *policy_file_entry);
void                   libpolkit_policy_file_entry_debug (PolKitPolicyFileEntry *policy_file_entry);

const char            *libpolkit_policy_file_entry_get_id      (PolKitPolicyFileEntry *policy_file_entry);
PolKitPolicyDefault   *libpolkit_policy_file_entry_get_default (PolKitPolicyFileEntry *policy_file_entry);


#endif /* LIBPOLKIT_POLICY_FILE_ENTRY_H */



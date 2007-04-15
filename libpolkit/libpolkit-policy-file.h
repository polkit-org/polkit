/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-file.h : policy files
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
#error "Only <libpolkit/libpolkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef LIBPOLKIT_POLICY_FILE_H
#define LIBPOLKIT_POLICY_FILE_H

#include <libpolkit/libpolkit-error.h>
#include <libpolkit/libpolkit-policy-file-entry.h>

struct PolKitPolicyFile;
typedef struct PolKitPolicyFile PolKitPolicyFile;

/**
 * PolKitPolicyFileEntryForeachFunc:
 * @policy_file: the policy file
 * @policy_file_entry: the entry
 * @user_data: user data
 *
 * Type for function used in libpolkit_policy_file_entry_foreach().
 **/
typedef void (*PolKitPolicyFileEntryForeachFunc) (PolKitPolicyFile      *policy_file, 
                                                  PolKitPolicyFileEntry *policy_file_entry,
                                                  void                  *user_data);

PolKitPolicyFile *libpolkit_policy_file_new           (const char       *path, PolKitError **error);
PolKitPolicyFile *libpolkit_policy_file_ref           (PolKitPolicyFile *policy_file);
void              libpolkit_policy_file_unref         (PolKitPolicyFile *policy_file);
void              libpolkit_policy_file_entry_foreach (PolKitPolicyFile                 *policy_file,
                                                       PolKitPolicyFileEntryForeachFunc  cb,
                                                       void                              *user_data);

#endif /* LIBPOLKIT_POLICY_FILE_H */



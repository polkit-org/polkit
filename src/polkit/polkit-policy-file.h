/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file.h : policy files
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

#ifndef POLKIT_POLICY_FILE_H
#define POLKIT_POLICY_FILE_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-error.h>
#include <polkit/polkit-policy-file-entry.h>

POLKIT_BEGIN_DECLS

struct _PolKitPolicyFile;
typedef struct _PolKitPolicyFile PolKitPolicyFile;

/**
 * PolKitPolicyFileEntryForeachFunc:
 * @policy_file: the policy file
 * @policy_file_entry: the entry
 * @user_data: user data
 *
 * Type for function used in polkit_policy_file_entry_foreach().
 *
 * Returns: #TRUE to short-circuit, e.g.  stop the iteration
 **/
typedef polkit_bool_t (*PolKitPolicyFileEntryForeachFunc) (PolKitPolicyFile      *policy_file, 
                                                           PolKitPolicyFileEntry *policy_file_entry,
                                                           void                  *user_data);

PolKitPolicyFile *polkit_policy_file_new           (const char       *path, 
                                                    polkit_bool_t load_descriptions, 
                                                    PolKitError **error);
PolKitPolicyFile *polkit_policy_file_ref           (PolKitPolicyFile *policy_file);
void              polkit_policy_file_unref         (PolKitPolicyFile *policy_file);
polkit_bool_t     polkit_policy_file_entry_foreach (PolKitPolicyFile                 *policy_file,
                                                    PolKitPolicyFileEntryForeachFunc  cb,
                                                    void                              *user_data);

POLKIT_END_DECLS

#endif /* POLKIT_POLICY_FILE_H */



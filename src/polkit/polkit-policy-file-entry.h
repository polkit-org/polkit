/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file-entry.h : entries in policy files
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

#ifndef POLKIT_POLICY_FILE_ENTRY_H
#define POLKIT_POLICY_FILE_ENTRY_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-policy-default.h>
#include <polkit/polkit-error.h>

POLKIT_BEGIN_DECLS

struct _PolKitPolicyFileEntry;
typedef struct _PolKitPolicyFileEntry PolKitPolicyFileEntry;

/**
 * PolKitPolicyFileEntryAnnotationsForeachFunc:
 * @policy_file_entry: the policy file entry
 * @key: key of the annotation
 * @value: corrosponding value of the annotation
 * @user_data: user data passed to polkit_policy_file_entry_annotations_foreach()
 *
 * Callback function for polkit_policy_file_entry_annotations_foreach().
 *
 * Returns: Pass #TRUE to short-circuit, e.g. stop the iteration
 **/
typedef polkit_bool_t (*PolKitPolicyFileEntryAnnotationsForeachFunc) (PolKitPolicyFileEntry *policy_file_entry,
                                                                      const char *key,
                                                                      const char *value,
                                                                      void *user_data);

PolKitPolicyFileEntry *polkit_policy_file_entry_ref   (PolKitPolicyFileEntry *policy_file_entry);
void                   polkit_policy_file_entry_unref (PolKitPolicyFileEntry *policy_file_entry);
void                   polkit_policy_file_entry_debug (PolKitPolicyFileEntry *policy_file_entry);

const char            *polkit_policy_file_entry_get_id       (PolKitPolicyFileEntry *policy_file_entry);
PolKitPolicyDefault   *polkit_policy_file_entry_get_default  (PolKitPolicyFileEntry *policy_file_entry);

const char            *polkit_policy_file_entry_get_action_description (PolKitPolicyFileEntry *policy_file_entry);
const char            *polkit_policy_file_entry_get_action_message (PolKitPolicyFileEntry *policy_file_entry);

const char            *polkit_policy_file_entry_get_action_vendor     (PolKitPolicyFileEntry *policy_file_entry);
const char            *polkit_policy_file_entry_get_action_vendor_url (PolKitPolicyFileEntry *policy_file_entry);
const char            *polkit_policy_file_entry_get_action_icon_name  (PolKitPolicyFileEntry *policy_file_entry);

polkit_bool_t          polkit_policy_file_entry_annotations_foreach (PolKitPolicyFileEntry *policy_file_entry,
                                                                     PolKitPolicyFileEntryAnnotationsForeachFunc cb,
                                                                     void *user_data);
const char            *polkit_policy_file_entry_get_annotation (PolKitPolicyFileEntry *policy_file_entry,
                                                                const char *key);

PolKitPolicyDefault   *polkit_policy_file_entry_get_default_factory (PolKitPolicyFileEntry  *policy_file_entry);
polkit_bool_t          polkit_policy_file_entry_set_default         (PolKitPolicyFileEntry  *policy_file_entry,
                                                                     PolKitPolicyDefault    *defaults,
                                                                     PolKitError           **error);

POLKIT_END_DECLS

#endif /* POLKIT_POLICY_FILE_ENTRY_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-file.c : policy files
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "libpolkit-error.h"
#include "libpolkit-result.h"
#include "libpolkit-policy-file.h"
#include "libpolkit-policy-file-entry.h"

/**
 * SECTION:libpolkit-policy-file
 * @short_description: Policy files.
 *
 * This class is used to represent a policy files.
 **/

/**
 * PolKitPolicyFile:
 *
 * Objects of this class are used to record information about a
 * policy file.
 **/
struct PolKitPolicyFile
{
        int refcount;
        GSList *entries;
};

extern PolKitPolicyFileEntry *_libpolkit_policy_file_entry_new   (GKeyFile *keyfile, 
                                                                  const char *action, 
                                                                  PolKitError **error);

/**
 * libpolkit_policy_file_new:
 * @path: path to policy file
 * @error: return location for error
 * 
 * Create a new #PolKitPolicyFile object. If the file does not
 * validate, a human readable explanation of why will be set in
 * @error.
 * 
 * Returns: the new object or #NULL if error is set
 **/
PolKitPolicyFile *
libpolkit_policy_file_new (const char *path, PolKitError **error)
{
        GKeyFile *key_file;
        PolKitPolicyFile *pf;
        char **groups;
        gsize groups_len;
        int n;
        GError *g_error;

        pf = NULL;
        key_file = NULL;
        groups = NULL;

        if (!g_str_has_suffix (path, ".policy")) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Policy files must have extension .policy; file '%s' doesn't", path);
                goto error;
        }

        g_error = NULL;
        key_file = g_key_file_new ();
        if (!g_key_file_load_from_file (key_file, path, G_KEY_FILE_NONE, &g_error)) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Cannot load PolicyKit policy file at '%s': %s",
                                        path,
                                        g_error->message);
                g_error_free (g_error);
                goto error;
        }

        pf = g_new0 (PolKitPolicyFile, 1);
        pf->refcount = 1;

        groups = g_key_file_get_groups(key_file, &groups_len);
        if (groups == NULL)
                goto error;

        for (n = 0; groups[n] != NULL; n++) {
                const char *action;
                PolKitPolicyFileEntry *pfe;

                if (!g_str_has_prefix (groups[n], "Action ")) {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_POLICY_FILE_INVALID,
                                                "Unknown group of name '%s'", groups[n]);
                        goto error;
                }

                action = groups[n] + 7; /* "Action " */
                if (strlen (action) == 0) {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_POLICY_FILE_INVALID,
                                                "Zero-length action name");
                        goto error;
                }

                pfe = _libpolkit_policy_file_entry_new (key_file, action, error);
                if (pfe == NULL)
                        goto error;
                pf->entries = g_slist_prepend (pf->entries, pfe);
        }

        g_strfreev (groups);
        g_key_file_free (key_file);
        return pf;
error:
        if (groups != NULL)
                g_strfreev (groups);
        if (key_file != NULL)
                g_key_file_free (key_file);
        if (pf != NULL)
                libpolkit_policy_file_unref (pf);
        return NULL;
}

/**
 * libpolkit_policy_file_ref:
 * @policy_file: the policy file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyFile *
libpolkit_policy_file_ref (PolKitPolicyFile *policy_file)
{
        g_return_val_if_fail (policy_file != NULL, policy_file);
        policy_file->refcount++;
        return policy_file;
}

/**
 * libpolkit_policy_file_unref:
 * @policy_file: the policy file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_policy_file_unref (PolKitPolicyFile *policy_file)
{
        GSList *i;
        g_return_if_fail (policy_file != NULL);
        policy_file->refcount--;
        if (policy_file->refcount > 0) 
                return;
        for (i = policy_file->entries; i != NULL; i = g_slist_next (i)) {
                libpolkit_policy_file_entry_unref (i->data);
        }
        if (policy_file->entries != NULL)
                g_slist_free (policy_file->entries);
        g_free (policy_file);
}

/**
 * libpolkit_policy_file_entry_foreach:
 * @policy_file: the policy file object
 * @cb: callback to invoke for each entry
 * @user_data: user data
 * 
 * Visits all entries in a policy file.
 **/
void
libpolkit_policy_file_entry_foreach (PolKitPolicyFile                 *policy_file,
                                     PolKitPolicyFileEntryForeachFunc  cb,
                                     void                              *user_data)
{
        GSList *i;

        g_return_if_fail (policy_file != NULL);
        g_return_if_fail (cb != NULL);

        for (i = policy_file->entries; i != NULL; i = g_slist_next (i)) {
                PolKitPolicyFileEntry *pfe = i->data;
                cb (policy_file, pfe, user_data);
        }
}

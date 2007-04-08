/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-file-entry.c : entries in policy files
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
#include "libpolkit-debug.h"
#include "libpolkit-error.h"
#include "libpolkit-result.h"
#include "libpolkit-policy-file-entry.h"

/**
 * SECTION:libpolkit-policy-file-entry
 * @short_description: Policy files entries.
 *
 * This class is used to represent a entries in policy files.
 **/

/**
 * PolKitPolicyFileEntry:
 *
 * Objects of this class are used to record information about a
 * policy.
 **/
struct PolKitPolicyFileEntry
{
        int refcount;
        char *action;
        PolKitPolicyDefault *defaults;
};

/**
 * libpolkit_policy_file_entry_new:
 * @key_file: a #GKeyFile object
 * @action: action to look for in key_file
 * @error: return location for error
 * 
 * Create a new #PolKitPolicyFileEntry object. If the given
 * @key_file object does not contain the requisite sections, a human
 * readable explanation of why will be set in @error.
 * 
 * Returns: the new object or #NULL if error is set
 **/
PolKitPolicyFileEntry *
libpolkit_policy_file_entry_new (GKeyFile *key_file, const char *action, GError **error)
{
        PolKitPolicyFileEntry *pfe;

        pfe = g_new0 (PolKitPolicyFileEntry, 1);
        pfe->refcount = 1;
        pfe->action = g_strdup (action);

        pfe->defaults = libpolkit_policy_default_new (key_file, action, error);
        if (pfe->defaults == NULL)
                goto error;

        return pfe;
error:
        if (pfe != NULL)
                libpolkit_policy_file_entry_unref (pfe);
        return NULL;
}

/**
 * libpolkit_policy_file_entry_ref:
 * @policy_file_entry: the policy file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyFileEntry *
libpolkit_policy_file_entry_ref (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, policy_file_entry);
        policy_file_entry->refcount++;
        return policy_file_entry;
}

/**
 * libpolkit_policy_file_entry_unref:
 * @policy_file_entry: the policy file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_policy_file_entry_unref (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_if_fail (policy_file_entry != NULL);
        policy_file_entry->refcount--;
        if (policy_file_entry->refcount > 0) 
                return;
        g_free (policy_file_entry->action);
        if (policy_file_entry->defaults != NULL)
                libpolkit_policy_default_unref (policy_file_entry->defaults);
        g_free (policy_file_entry);
}

/**
 * libpolkit_policy_file_entry_debug:
 * @policy_file_entry: the entry
 * 
 * Print debug information about object
 **/
void
libpolkit_policy_file_entry_debug (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_if_fail (policy_file_entry != NULL);
        _pk_debug ("PolKitPolicyFileEntry: refcount=%d action=%s",
                   policy_file_entry->refcount,
                   policy_file_entry->action);
        libpolkit_policy_default_debug (policy_file_entry->defaults);
}

/**
 * libpolkit_policy_file_entry_get_id:
 * @policy_file_entry: the file entry
 * 
 * Get the action identifier.
 * 
 * Returns: A string - caller shall not free this string.
 **/
const char *
libpolkit_policy_file_entry_get_id (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->action;
}

/**
 * libpolkit_policy_file_entry_get_default:
 * @policy_file_entry: the file entry
 * 
 * Get the the default policy for this policy.
 * 
 * Returns: A #PolKitPolicyDefault object - caller shall not unref this object.
 **/
PolKitPolicyDefault *
libpolkit_policy_file_entry_get_default (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->defaults;
}

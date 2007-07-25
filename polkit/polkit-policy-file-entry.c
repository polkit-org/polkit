/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file-entry.c : entries in policy files
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
#include "polkit-debug.h"
#include "polkit-error.h"
#include "polkit-result.h"
#include "polkit-policy-file-entry.h"

/**
 * SECTION:polkit-policy-file-entry
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
        char *group;
        PolKitPolicyDefault *defaults;

        char *group_description;
        char *policy_description;
        char *policy_message;
};

extern void _polkit_policy_file_entry_set_descriptions (PolKitPolicyFileEntry *pfe,
                                                        const char *group_description,
                                                        const char *policy_description,
                                                        const char *policy_message);


extern PolKitPolicyDefault *_polkit_policy_default_new (PolKitResult defaults_allow_inactive,
                                                        PolKitResult defaults_allow_active);

extern PolKitPolicyFileEntry *_polkit_policy_file_entry_new   (const char *action_group_id,
                                                               const char *action_id, 
                                                               PolKitResult defaults_allow_inactive,
                                                               PolKitResult defaults_allow_active);

extern PolKitPolicyFileEntry *
_polkit_policy_file_entry_new   (const char *action_group_id,
                                 const char *action_id, 
                                 PolKitResult defaults_allow_inactive,
                                 PolKitResult defaults_allow_active)
{
        PolKitPolicyFileEntry *pfe;

        pfe = g_new0 (PolKitPolicyFileEntry, 1);
        pfe->refcount = 1;
        pfe->action = g_strdup (action_id);
        pfe->group = g_strdup (action_group_id);

        pfe->defaults = _polkit_policy_default_new (defaults_allow_inactive,
                                                    defaults_allow_active);
        if (pfe->defaults == NULL)
                goto error;

        return pfe;
error:
        if (pfe != NULL)
                polkit_policy_file_entry_unref (pfe);
        return NULL;
}

void 
_polkit_policy_file_entry_set_descriptions (PolKitPolicyFileEntry *policy_file_entry,
                                            const char *group_description,
                                            const char *policy_description,
                                            const char *policy_message)
{
        g_return_if_fail (policy_file_entry != NULL);
        policy_file_entry->group_description = g_strdup (group_description);
        policy_file_entry->policy_description = g_strdup (policy_description);
        policy_file_entry->policy_message = g_strdup (policy_message);
}

/**
 * polkit_policy_file_get_group_description:
 * @policy_file_entry: the object
 * 
 * Get the description of the group that this policy entry describes.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_get_group_description (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->group_description;
}

/**
 * polkit_policy_file_get_action_description:
 * @policy_file_entry: the object
 * 
 * Get the description of the action that this policy entry describes. This
 * is intended to be used in policy editors, for example "Mount internal
 * volumes". Contrast with polkit_policy_file_get_action_message(). The
 * textual string will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_get_action_description (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->policy_description;
}

/**
 * polkit_policy_file_get_action_message:
 * @policy_file_entry: the object
 * 
 * Get the message describing the action that this policy entry
 * describes. This is to be used in dialogs, for example "System
 * Policy prevents mounting this volume". Contrast with
 * polkit_policy_file_get_action_description(). The textual string
 * will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_get_action_message (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->policy_message;
}

/**
 * polkit_policy_file_entry_ref:
 * @policy_file_entry: the policy file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyFileEntry *
polkit_policy_file_entry_ref (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, policy_file_entry);
        policy_file_entry->refcount++;
        return policy_file_entry;
}

/**
 * polkit_policy_file_entry_unref:
 * @policy_file_entry: the policy file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_policy_file_entry_unref (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_if_fail (policy_file_entry != NULL);
        policy_file_entry->refcount--;
        if (policy_file_entry->refcount > 0) 
                return;
        g_free (policy_file_entry->action);
        if (policy_file_entry->defaults != NULL)
                polkit_policy_default_unref (policy_file_entry->defaults);

        g_free (policy_file_entry->group_description);
        g_free (policy_file_entry->policy_description);

        g_free (policy_file_entry);
}

/**
 * polkit_policy_file_entry_debug:
 * @policy_file_entry: the entry
 * 
 * Print debug information about object
 **/
void
polkit_policy_file_entry_debug (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_if_fail (policy_file_entry != NULL);
        _pk_debug ("PolKitPolicyFileEntry: refcount=%d action=%s",
                   policy_file_entry->refcount,
                   policy_file_entry->action);
        polkit_policy_default_debug (policy_file_entry->defaults);
}

/**
 * polkit_policy_file_entry_get_id:
 * @policy_file_entry: the file entry
 * 
 * Get the action identifier.
 * 
 * Returns: A string - caller shall not free this string.
 **/
const char *
polkit_policy_file_entry_get_id (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->action;
}

/**
 * polkit_policy_file_entry_get_group_id:
 * @policy_file_entry: the file entry
 * 
 * Get the action group identifier.
 * 
 * Returns: A string - caller shall not free this string.
 **/
const char *
polkit_policy_file_entry_get_group_id (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->group;
}


/**
 * polkit_policy_file_entry_get_default:
 * @policy_file_entry: the file entry
 * 
 * Get the the default policy for this policy.
 * 
 * Returns: A #PolKitPolicyDefault object - caller shall not unref this object.
 **/
PolKitPolicyDefault *
polkit_policy_file_entry_get_default (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->defaults;
}

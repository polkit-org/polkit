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
#include "polkit-authorization-db.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-memory.h"

/**
 * SECTION:polkit-policy-file-entry
 * @title: Policy File Entry
 * @short_description: Represents a declared action in a policy file.
 *
 * This class is used to represent a entries in policy files.
 **/

/**
 * PolKitPolicyFileEntry:
 *
 * Objects of this class are used to record information about a
 * policy.
 **/
struct _PolKitPolicyFileEntry
{
        int refcount;
        char *action;
        PolKitPolicyDefault *defaults;

        char *policy_description;
        char *policy_message;
        GHashTable *annotations;
};


/* NOTE: we take ownership of the annotations object */
PolKitPolicyFileEntry *
_polkit_policy_file_entry_new   (const char *action_id, 
                                 PolKitResult defaults_allow_any,
                                 PolKitResult defaults_allow_inactive,
                                 PolKitResult defaults_allow_active,
                                 GHashTable *annotations)
{
        PolKitPolicyFileEntry *pfe;

        g_return_val_if_fail (action_id != NULL, NULL);

        pfe = p_new0 (PolKitPolicyFileEntry, 1);
        if (pfe == NULL)
                goto error;
        pfe->refcount = 1;
        pfe->action = p_strdup (action_id);
        if (pfe->action == NULL)
                goto error;

        if (! (polkit_authorization_db_get_capabilities () & POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN)) {
                /* if we don't support obtaining authorizations
                 * through authenticating, then make the defaults
                 * reflect this ...*/
                defaults_allow_any = POLKIT_RESULT_NO;
                defaults_allow_inactive = POLKIT_RESULT_NO;
                defaults_allow_active = POLKIT_RESULT_NO;
        }

        pfe->defaults = _polkit_policy_default_new (defaults_allow_any,
                                                    defaults_allow_inactive,
                                                    defaults_allow_active);
        if (pfe->defaults == NULL)
                goto error;

        pfe->annotations = annotations;

        return pfe;
error:
        if (pfe != NULL)
                polkit_policy_file_entry_unref (pfe);
        return NULL;
}

polkit_bool_t
_polkit_policy_file_entry_set_descriptions (PolKitPolicyFileEntry *pfe,
                                            const char *policy_description,
                                            const char *policy_message)
{
        g_return_val_if_fail (pfe != NULL, FALSE);

        if (pfe->policy_description != NULL)
                p_free (pfe->policy_description);
        if (pfe->policy_message != NULL)
                p_free (pfe->policy_message);

        pfe->policy_description = p_strdup (policy_description);
        pfe->policy_message = p_strdup (policy_message);

        if (policy_description != NULL && pfe->policy_description == NULL)
                return FALSE;

        if (policy_message != NULL && pfe->policy_message == NULL)
                return FALSE;

        return TRUE;
}

/**
 * polkit_policy_file_entry_get_action_description:
 * @policy_file_entry: the object
 * 
 * Get the description of the action that this policy entry describes. This
 * is intended to be used in policy editors, for example "Mount internal
 * volumes". Contrast with polkit_policy_file_entry_get_action_message(). The
 * textual string will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_entry_get_action_description (PolKitPolicyFileEntry *policy_file_entry)
{
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->policy_description;
}

/**
 * polkit_policy_file_entry_get_action_message:
 * @policy_file_entry: the object
 * 
 * Get the message describing the action that this policy entry
 * describes. This is to be used in dialogs, for example "System
 * Policy prevents mounting this volume". Contrast with
 * polkit_policy_file_entry_get_action_description(). The textual string
 * will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_entry_get_action_message (PolKitPolicyFileEntry *policy_file_entry)
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

        p_free (policy_file_entry->action);

        if (policy_file_entry->defaults != NULL)
                polkit_policy_default_unref (policy_file_entry->defaults);

        if (policy_file_entry->annotations != NULL)
                g_hash_table_destroy (policy_file_entry->annotations);

        p_free (policy_file_entry->policy_description);
        p_free (policy_file_entry->policy_message);

        p_free (policy_file_entry);
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

typedef struct  {
        PolKitPolicyFileEntry *pfe;
        PolKitPolicyFileEntryAnnotationsForeachFunc cb;
        void *user_data;
} _AnnotationsClosure;

static void
_annotations_cb (gpointer key,
                 gpointer value,
                 gpointer user_data)
{
        _AnnotationsClosure *closure = user_data;
        closure->cb (closure->pfe, (const char *) key, (const char *) value, closure->user_data);
}

/**
 * polkit_policy_file_entry_annotations_foreach:
 * @policy_file_entry: the policy file entry
 * @cb: callback function
 * @user_data: user data to pass to the callback function
 *
 * Iterate over all annotations on the policy file entry.
 */
void
polkit_policy_file_entry_annotations_foreach (PolKitPolicyFileEntry *policy_file_entry,
                                              PolKitPolicyFileEntryAnnotationsForeachFunc cb,
                                              void *user_data)
{
        _AnnotationsClosure closure;

        g_return_if_fail (policy_file_entry != NULL);
        if (policy_file_entry->annotations == NULL)
                return;

        closure.pfe = policy_file_entry;
        closure.cb = cb;
        closure.user_data = user_data;

        g_hash_table_foreach (policy_file_entry->annotations,
                              _annotations_cb,
                              &closure);
}

/**
 * polkit_policy_file_entry_get_annotation:
 * @policy_file_entry: the policy file entry
 * @key: the key of the annotation
 *
 * Look of the value of a given annotation.
 *
 * Returns: The value of the annotation or NULL if not found.
 */
const char *
polkit_policy_file_entry_get_annotation (PolKitPolicyFileEntry *policy_file_entry,
                                         const char *key)
{
        const char *value;
        g_return_val_if_fail (policy_file_entry != NULL, NULL);
        g_return_val_if_fail (key != NULL, NULL);

        value = NULL;
        if (policy_file_entry->annotations != NULL) {
                value = g_hash_table_lookup (policy_file_entry->annotations, key);
        }
        return value;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        PolKitPolicyFileEntry *pfe;
        PolKitPolicyDefault *d;

        if ((pfe = _polkit_policy_file_entry_new ("org.example-action",
                                                  POLKIT_RESULT_NO,
                                                  POLKIT_RESULT_ONLY_VIA_SELF_AUTH,
                                                  POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH,
                                                  NULL)) != NULL) {

                g_assert (strcmp (polkit_policy_file_entry_get_id (pfe), "org.example-action") == 0);

                if (_polkit_policy_file_entry_set_descriptions (pfe,
                                                                "the desc",
                                                                "the msg")) {
                        g_assert (strcmp (polkit_policy_file_entry_get_action_description (pfe), "the desc") == 0);
                        g_assert (strcmp (polkit_policy_file_entry_get_action_message (pfe), "the msg") == 0);
                }

                if (_polkit_policy_file_entry_set_descriptions (pfe,
                                                                "the desc2",
                                                                "the msg2")) {
                        g_assert (strcmp (polkit_policy_file_entry_get_action_description (pfe), "the desc2") == 0);
                        g_assert (strcmp (polkit_policy_file_entry_get_action_message (pfe), "the msg2") == 0);
                }

                g_assert ((d = polkit_policy_file_entry_get_default (pfe)) != NULL);
                g_assert (polkit_policy_default_get_allow_any (d) == POLKIT_RESULT_NO);
                g_assert (polkit_policy_default_get_allow_inactive (d) == POLKIT_RESULT_ONLY_VIA_SELF_AUTH);
                g_assert (polkit_policy_default_get_allow_active (d) == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH);

                polkit_policy_file_entry_ref (pfe);
                polkit_policy_file_entry_unref (pfe);
                polkit_policy_file_entry_debug (pfe);
                polkit_policy_file_entry_unref (pfe);
        }

        return TRUE;
}

PolKitTest _test_policy_file_entry = {
        "polkit_policy_file_entry",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

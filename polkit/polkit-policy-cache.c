/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-cache.c : policy cache
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
#include <syslog.h>

#include <glib.h>
#include "polkit-debug.h"
#include "polkit-policy-file.h"
#include "polkit-policy-cache.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-policy-cache
 * @title: Policy Cache
 * @short_description: Holds the actions defined on the system.
 *
 * This class is used to hold all policy objects (stemming from policy
 * files) and provide look-up functions.
 **/

/**
 * PolKitPolicyCache:
 *
 * Instances of this class are used to hold all policy objects
 * (stemming from policy files) and provide look-up functions.
 **/
struct _PolKitPolicyCache
{
        int refcount;

        GSList *priv_entries;
};


static void
_append_entry (PolKitPolicyFile       *policy_file,
               PolKitPolicyFileEntry  *policy_file_entry,
               void                   *user_data)
{
        PolKitPolicyCache *policy_cache = user_data;

        polkit_policy_file_entry_ref (policy_file_entry);
        policy_cache->priv_entries = g_slist_append (policy_cache->priv_entries, policy_file_entry);
}

PolKitPolicyCache *
_polkit_policy_cache_new (const char *dirname, polkit_bool_t load_descriptions, PolKitError **error)
{
        const char *file;
        GDir *dir;
        PolKitPolicyCache *pc;
        GError *g_error;

        pc = g_new0 (PolKitPolicyCache, 1);
        pc->refcount = 1;

        g_error = NULL;
        dir = g_dir_open (dirname, 0, &g_error);
        if (dir == NULL) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Cannot load policy files from directory %s: %s",
                                        dirname,
                                        g_error->message);
                g_error_free (g_error);
                goto out;
        }
        while ((file = g_dir_read_name (dir)) != NULL) {
                char *path;
                PolKitPolicyFile *pf;
                PolKitError *pk_error;

                if (!g_str_has_suffix (file, ".policy"))
                        continue;

                if (g_str_has_prefix (file, "."))
                        continue;

                path = g_strdup_printf ("%s/%s", dirname, file);

                _pk_debug ("Loading %s", path);
                pk_error = NULL;
                pf = polkit_policy_file_new (path, load_descriptions, &pk_error);
                g_free (path);

                if (pf == NULL) {
                        _pk_debug ("libpolkit: ignoring malformed policy file: %s", 
                                   polkit_error_get_error_message (pk_error));
                        syslog (LOG_ALERT, "libpolkit: ignoring malformed policy file: %s", 
                                polkit_error_get_error_message (pk_error));
                        polkit_error_free (pk_error);
                        continue;
                }

                /* steal entries */
                polkit_policy_file_entry_foreach (pf, _append_entry, pc);
                polkit_policy_file_unref (pf);
        }
        g_dir_close (dir);

        return pc;
out:
        if (pc != NULL)
                polkit_policy_cache_ref (pc);
        return NULL;
}

/**
 * polkit_policy_cache_ref:
 * @policy_cache: the policy cache object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyCache *
polkit_policy_cache_ref (PolKitPolicyCache *policy_cache)
{
        g_return_val_if_fail (policy_cache != NULL, policy_cache);
        policy_cache->refcount++;
        return policy_cache;
}

/**
 * polkit_policy_cache_unref:
 * @policy_cache: the policy cache object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_policy_cache_unref (PolKitPolicyCache *policy_cache)
{
        GSList *i;

        g_return_if_fail (policy_cache != NULL);
        policy_cache->refcount--;
        if (policy_cache->refcount > 0) 
                return;

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                PolKitPolicyFileEntry *pfe = i->data;
                polkit_policy_file_entry_unref (pfe);
        }
        if (policy_cache->priv_entries != NULL)
                g_slist_free (policy_cache->priv_entries);

        g_free (policy_cache);
}

/**
 * polkit_policy_cache_debug:
 * @policy_cache: the cache
 * 
 * Print debug information about object
 **/
void
polkit_policy_cache_debug (PolKitPolicyCache *policy_cache)
{
        GSList *i;
        g_return_if_fail (policy_cache != NULL);

        _pk_debug ("PolKitPolicyCache: refcount=%d num_entries=%d ...", 
                   policy_cache->refcount,
                   policy_cache->priv_entries == NULL ? 0 : g_slist_length (policy_cache->priv_entries));

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                PolKitPolicyFileEntry *pfe = i->data;
                polkit_policy_file_entry_debug (pfe);
        }
}

/**
 * polkit_policy_cache_get_entry_by_id:
 * @policy_cache: the cache
 * @action_id: the action identifier
 * 
 * Given a action identifier, find the object describing the
 * definition of the policy; e.g. data stemming from files in
 * /usr/share/PolicyKit/policy.
 * 
 * Returns: A #PolKitPolicyFileEntry entry on sucess; otherwise
 * #NULL if the action wasn't identified. Caller shall not unref
 * this object.
 **/
PolKitPolicyFileEntry* 
polkit_policy_cache_get_entry_by_id (PolKitPolicyCache *policy_cache, const char *action_id)
{
        GSList *i;
        PolKitPolicyFileEntry *pfe;

        g_return_val_if_fail (policy_cache != NULL, NULL);
        g_return_val_if_fail (action_id != NULL, NULL);

        pfe = NULL;

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                pfe = i->data;
                if (strcmp (polkit_policy_file_entry_get_id (pfe), action_id) == 0) {
                        goto out;
                }
        }

        pfe = NULL;

out:
        return pfe;        
}

/**
 * polkit_policy_cache_get_entry:
 * @policy_cache: the cache
 * @action: the action
 * 
 * Given a action, find the object describing the definition of the
 * policy; e.g. data stemming from files in
 * /usr/share/PolicyKit/policy.
 * 
 * Returns: A #PolKitPolicyFileEntry entry on sucess; otherwise
 * #NULL if the action wasn't identified. Caller shall not unref
 * this object.
 **/
PolKitPolicyFileEntry* 
polkit_policy_cache_get_entry (PolKitPolicyCache *policy_cache,
                                  PolKitAction      *action)
{
        char *action_id;
        PolKitPolicyFileEntry *pfe;

        /* I'm sure it would be easy to make this O(1)... */

        g_return_val_if_fail (policy_cache != NULL, NULL);
        g_return_val_if_fail (action != NULL, NULL);

        pfe = NULL;

        if (!polkit_action_get_action_id (action, &action_id))
                goto out;

        pfe = polkit_policy_cache_get_entry_by_id (policy_cache, action_id);
out:
        return pfe;
}

/**
 * polkit_policy_cache_foreach:
 * @policy_cache: the policy cache
 * @callback: callback function
 * @user_data: user data to pass to callback function
 * 
 * Visit all entries in the policy cache.
 **/
void
polkit_policy_cache_foreach (PolKitPolicyCache *policy_cache, 
                             PolKitPolicyCacheForeachFunc callback,
                             void *user_data)
{
        GSList *i;
        PolKitPolicyFileEntry *pfe;

        g_return_if_fail (policy_cache != NULL);
        g_return_if_fail (callback != NULL);

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                pfe = i->data;
                callback (policy_cache, pfe, user_data);
        }
}

/**
 * polkit_policy_cache_get_entry_by_annotation:
 * @policy_cache: the policy cache
 * @annotation_key: the key to check for
 * @annotation_value: the value to check for
 *
 * Find the first policy file entry where a given annotation matches a
 * given value. Note that there is nothing preventing the existence of
 * multiple policy file entries matching this criteria; it would
 * however be a packaging bug if this situation occured.
 *
 * Returns: The first #PolKitPolicyFileEntry matching the search
 * criteria. The caller shall not unref this object. Returns #NULL if
 * there are no policy file entries matching the search criteria.
 *
 * Since: 0.7
 */
PolKitPolicyFileEntry* 
polkit_policy_cache_get_entry_by_annotation (PolKitPolicyCache *policy_cache, 
                                             const char *annotation_key,
                                             const char *annotation_value)
{
        GSList *i;

        g_return_val_if_fail (policy_cache != NULL, NULL);
        g_return_val_if_fail (annotation_key != NULL, NULL);
        g_return_val_if_fail (annotation_value != NULL, NULL);

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                const char *value;
                PolKitPolicyFileEntry *pfe = i->data;

                value = polkit_policy_file_entry_get_annotation (pfe, annotation_key);
                if (value == NULL)
                        continue;

                if (strcmp (annotation_value, value) == 0) {
                        return pfe;
                }
        }

        return NULL;
}

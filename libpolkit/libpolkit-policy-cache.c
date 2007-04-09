/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-cache.c : policy cache
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
#include "libpolkit-policy-file.h"
#include "libpolkit-policy-cache.h"

/**
 * SECTION:libpolkit-policy-cache
 * @short_description: Class for holding all policy objects.
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
struct PolKitPolicyCache
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

        libpolkit_policy_file_entry_ref (policy_file_entry);
        policy_cache->priv_entries = g_slist_append (policy_cache->priv_entries, policy_file_entry);
}

/**
 * libpolkit_policy_cache_new:
 * @dirname: directory containing policy files
 * @error: location to return error
 * 
 * Create a new #PolKitPolicyCache object and load information from policy files.
 * 
 * Returns: #NULL if @error was set, otherwise the #PolKitPolicyCache object
 **/
PolKitPolicyCache *
libpolkit_policy_cache_new (const char *dirname, PolKitError **error)
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

                if (!g_str_has_suffix (file, ".policy"))
                        continue;

                if (g_str_has_prefix (file, "."))
                        continue;

                path = g_strdup_printf ("%s/%s", dirname, file);

                _pk_debug ("Loading %s", path);
                pf = libpolkit_policy_file_new (path, error);
                g_free (path);

                if (pf == NULL) {
                        goto out;
                }

                /* steal entries */
                libpolkit_policy_file_entry_foreach (pf, _append_entry, pc);
                libpolkit_policy_file_unref (pf);
        }
        g_dir_close (dir);

        return pc;
out:
        if (pc != NULL)
                libpolkit_policy_cache_ref (pc);
        return NULL;
}

/**
 * libpolkit_policy_cache_ref:
 * @policy_cache: the policy cache object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyCache *
libpolkit_policy_cache_ref (PolKitPolicyCache *policy_cache)
{
        g_return_val_if_fail (policy_cache != NULL, policy_cache);
        policy_cache->refcount++;
        return policy_cache;
}

/**
 * libpolkit_policy_cache_unref:
 * @policy_cache: the policy cache object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_policy_cache_unref (PolKitPolicyCache *policy_cache)
{
        GSList *i;

        g_return_if_fail (policy_cache != NULL);
        policy_cache->refcount--;
        if (policy_cache->refcount > 0) 
                return;

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                PolKitPolicyFileEntry *pfe = i->data;
                libpolkit_policy_file_entry_unref (pfe);
        }
        if (policy_cache->priv_entries != NULL)
                g_slist_free (policy_cache->priv_entries);

        g_free (policy_cache);
}

/**
 * libpolkit_policy_cache_debug:
 * @policy_cache: the cache
 * 
 * Print debug information about object
 **/
void
libpolkit_policy_cache_debug (PolKitPolicyCache *policy_cache)
{
        GSList *i;
        g_return_if_fail (policy_cache != NULL);

        _pk_debug ("PolKitPolicyCache: refcount=%d num_entries=%d ...", 
                   policy_cache->refcount,
                   policy_cache->priv_entries == NULL ? 0 : g_slist_length (policy_cache->priv_entries));

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                PolKitPolicyFileEntry *pfe = i->data;
                libpolkit_policy_file_entry_debug (pfe);
        }
}

/**
 * libpolkit_policy_cache_get_entry:
 * @policy_cache: the cache
 * @action: the action
 * 
 * Given a action, find the object describing the definition of the
 * policy; e.g. data stemming from files in
 * /etc/PolicyKit/policy.
 * 
 * Returns: A #PolKitPolicyFileEntry entry on sucess; otherwise
 * #NULL if the action wasn't identified. Caller shall not unref
 * this object.
 **/
PolKitPolicyFileEntry* 
libpolkit_policy_cache_get_entry (PolKitPolicyCache *policy_cache,
                                  PolKitAction      *action)
{
        char *priv_id;
        GSList *i;
        PolKitPolicyFileEntry *pfe;

        pfe = NULL;

        /* I'm sure it would be easy to make this O(1)... */

        g_return_val_if_fail (policy_cache != NULL, NULL);
        g_return_val_if_fail (action != NULL, NULL);

        if (!libpolkit_action_get_action_id (action, &priv_id))
                goto out;

        for (i = policy_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                pfe = i->data;
                if (strcmp (libpolkit_policy_file_entry_get_id (pfe), priv_id) == 0) {
                        goto out;
                }
        }

        pfe = NULL;

out:
        return pfe;
}

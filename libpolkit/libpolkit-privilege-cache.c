/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege-cache.c : privilege cache
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
#include "libpolkit-privilege-file.h"
#include "libpolkit-privilege-cache.h"

/**
 * SECTION:libpolkit-privilege-cache
 * @short_description: System privilege queries.
 *
 * This class is used to query all system-defined privileges,
 * e.g. privilege files installed in /etc/PolicyKit/privileges.
 **/

/**
 * PolKitPrivilegeCache:
 *
 * Instances of this class is used to query all system-defined
 * privileges, e.g. privilege files installed in
 * /etc/PolicyKit/privileges.
 **/
struct PolKitPrivilegeCache
{
        int refcount;

        GSList *priv_entries;
};


static void
add_entries_from_file (PolKitPrivilegeCache *privilege_cache,
                       PolKitPrivilegeFile  *privilege_file)
{
        GSList *i;

        g_return_if_fail (privilege_cache != NULL);
        g_return_if_fail (privilege_file != NULL);

        for (i = libpolkit_privilege_file_get_entries (privilege_file); i != NULL; i = g_slist_next (i)) {
                PolKitPrivilegeFileEntry  *privilege_file_entry = i->data;
                libpolkit_privilege_file_entry_ref (privilege_file_entry);
                privilege_cache->priv_entries = g_slist_append (privilege_cache->priv_entries, 
                                                                privilege_file_entry);
        }
}

/**
 * libpolkit_privilege_cache_new:
 * @dirname: directory containing privilege files
 * @error: location to return error
 * 
 * Create a new #PolKitPrivilegeCache object and load information from privilege files.
 * 
 * Returns: #NULL if @error was set, otherwise the #PolKitPrivilegeCache object
 **/
PolKitPrivilegeCache *
libpolkit_privilege_cache_new (const char *dirname, GError **error)
{
        const char *file;
        GDir *dir;
        PolKitPrivilegeCache *pc;

        pc = g_new0 (PolKitPrivilegeCache, 1);
        pc->refcount = 1;

        dir = g_dir_open (dirname, 0, error);
        if (dir == NULL) {
                goto out;
        }
        while ((file = g_dir_read_name (dir)) != NULL) {
                char *path;
                PolKitPrivilegeFile *pf;

                if (!g_str_has_suffix (file, ".priv"))
                        continue;

                if (g_str_has_suffix (file, "."))
                        continue;

                path = g_strdup_printf ("%s/%s", dirname, file);

                _pk_debug ("Loading %s", path);
                pf = libpolkit_privilege_file_new (path, error);
                g_free (path);

                if (pf == NULL) {
                        goto out;
                }

                add_entries_from_file (pc, pf);
                libpolkit_privilege_file_unref (pf);
        }
        g_dir_close (dir);

        return pc;
out:
        if (pc != NULL)
                libpolkit_privilege_cache_ref (pc);
        return NULL;
}

/**
 * libpolkit_privilege_cache_ref:
 * @privilege_cache: the privilege cache object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPrivilegeCache *
libpolkit_privilege_cache_ref (PolKitPrivilegeCache *privilege_cache)
{
        g_return_val_if_fail (privilege_cache != NULL, privilege_cache);
        privilege_cache->refcount++;
        return privilege_cache;
}

/**
 * libpolkit_privilege_cache_unref:
 * @privilege_cache: the privilege cache object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_privilege_cache_unref (PolKitPrivilegeCache *privilege_cache)
{
        GSList *i;

        g_return_if_fail (privilege_cache != NULL);
        privilege_cache->refcount--;
        if (privilege_cache->refcount > 0) 
                return;

        for (i = privilege_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                PolKitPrivilegeFileEntry *pfe = i->data;
                libpolkit_privilege_file_entry_unref (pfe);
        }
        if (privilege_cache->priv_entries != NULL)
                g_slist_free (privilege_cache->priv_entries);

        g_free (privilege_cache);
}

/**
 * libpolkit_privilege_cache_debug:
 * @privilege_cache: the cache
 * 
 * Print debug information about object
 **/
void
libpolkit_privilege_cache_debug (PolKitPrivilegeCache *privilege_cache)
{
        GSList *i;
        g_return_if_fail (privilege_cache != NULL);

        _pk_debug ("PolKitPrivilegeCache: refcount=%d num_entries=%d ...", 
                   privilege_cache->refcount,
                   privilege_cache->priv_entries == NULL ? 0 : g_slist_length (privilege_cache->priv_entries));

        for (i = privilege_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                PolKitPrivilegeFileEntry *pfe = i->data;
                libpolkit_privilege_file_entry_debug (pfe);
        }
}

/**
 * libpolkit_privilege_cache_get_entry:
 * @privilege_cache: the cache
 * @privilege: the privilege
 * 
 * Given a privilege, find the object describing the definition of the
 * privilege; e.g. data stemming from files in
 * /etc/PolicyKit/privileges.
 * 
 * Returns: A #PolKitPrivilegeFileEntry entry on sucess; otherwise
 * #NULL if the privilege wasn't identified. Caller shall not unref
 * this object.
 **/
PolKitPrivilegeFileEntry* 
libpolkit_privilege_cache_get_entry (PolKitPrivilegeCache *privilege_cache,
                                     PolKitPrivilege      *privilege)
{
        char *priv_id;
        GSList *i;
        PolKitPrivilegeFileEntry *pfe;

        pfe = NULL;

        /* I'm sure it would be easy to make this O(1)... */

        g_return_val_if_fail (privilege_cache != NULL, NULL);
        g_return_val_if_fail (privilege != NULL, NULL);

        if (!libpolkit_privilege_get_privilege_id (privilege, &priv_id))
                goto out;

        for (i = privilege_cache->priv_entries; i != NULL; i = g_slist_next (i)) {
                pfe = i->data;
                if (strcmp (libpolkit_privilege_file_entry_get_id (pfe), priv_id) == 0) {
                        goto out;
                }
        }

        pfe = NULL;

out:
        return pfe;
}

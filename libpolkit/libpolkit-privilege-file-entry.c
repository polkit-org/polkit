/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege-file-entry.c : entries in privilege files
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
#include "libpolkit-privilege-file-entry.h"

/**
 * SECTION:libpolkit-privilege-file-entry
 * @short_description: Privileges files.
 *
 * This class is used to represent a entries in privilege files.
 **/

/**
 * PolKitPrivilegeFileEntry:
 *
 * Objects of this class are used to record information about a
 * privilege.
 **/
struct PolKitPrivilegeFileEntry
{
        int refcount;
        char *privilege;
        PolKitPrivilegeDefault *defaults;
};

/**
 * libpolkit_privilege_file_entry_new:
 * @key_file: a #GKeyFile object
 * @privilege: privilege to look for in key_file
 * @error: return location for error
 * 
 * Create a new #PolKitPrivilegeFileEntry object. If the given
 * @key_file object does not contain the requisite sections, a human
 * readable explanation of why will be set in @error.
 * 
 * Returns: the new object or #NULL if error is set
 **/
PolKitPrivilegeFileEntry *
libpolkit_privilege_file_entry_new (GKeyFile *key_file, const char *privilege, GError **error)
{
        PolKitPrivilegeFileEntry *pfe;

        pfe = g_new0 (PolKitPrivilegeFileEntry, 1);
        pfe->refcount = 1;
        pfe->privilege = g_strdup (privilege);

        pfe->defaults = libpolkit_privilege_default_new (key_file, privilege, error);
        if (pfe->defaults == NULL)
                goto error;

        return pfe;
error:
        if (pfe != NULL)
                libpolkit_privilege_file_entry_unref (pfe);
        return NULL;
}

/**
 * libpolkit_privilege_file_entry_ref:
 * @privilege_file_entry: the privilege file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPrivilegeFileEntry *
libpolkit_privilege_file_entry_ref (PolKitPrivilegeFileEntry *privilege_file_entry)
{
        g_return_val_if_fail (privilege_file_entry != NULL, privilege_file_entry);
        privilege_file_entry->refcount++;
        return privilege_file_entry;
}

/**
 * libpolkit_privilege_file_entry_unref:
 * @privilege_file_entry: the privilege file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_privilege_file_entry_unref (PolKitPrivilegeFileEntry *privilege_file_entry)
{
        g_return_if_fail (privilege_file_entry != NULL);
        privilege_file_entry->refcount--;
        if (privilege_file_entry->refcount > 0) 
                return;
        g_free (privilege_file_entry->privilege);
        if (privilege_file_entry->defaults != NULL)
                libpolkit_privilege_default_unref (privilege_file_entry->defaults);
        g_free (privilege_file_entry);
}

/**
 * libpolkit_privilege_file_entry_debug:
 * @privilege_file_entry: the entry
 * 
 * Print debug information about object
 **/
void
libpolkit_privilege_file_entry_debug (PolKitPrivilegeFileEntry *privilege_file_entry)
{
        g_return_if_fail (privilege_file_entry != NULL);
        g_debug ("PolKitPrivilegeFileEntry: refcount=%d privilege=%s",
                 privilege_file_entry->refcount,
                 privilege_file_entry->privilege);
        libpolkit_privilege_default_debug (privilege_file_entry->defaults);
}

/**
 * libpolkit_privilege_file_entry_get_id:
 * @privilege_file_entry: the file entry
 * 
 * Get the privilege identifier.
 * 
 * Returns: A string - caller shall not free this string.
 **/
const char *
libpolkit_privilege_file_entry_get_id (PolKitPrivilegeFileEntry *privilege_file_entry)
{
        g_return_val_if_fail (privilege_file_entry != NULL, NULL);
        return privilege_file_entry->privilege;
}

/**
 * libpolkit_privilege_file_entry_get_default:
 * @privilege_file_entry: the file entry
 * 
 * Get the the default policy for this privilege.
 * 
 * Returns: A #PolKitPrivilegeDefault object - caller shall not unref this object.
 **/
PolKitPrivilegeDefault *
libpolkit_privilege_file_entry_get_default (PolKitPrivilegeFileEntry *privilege_file_entry)
{
        g_return_val_if_fail (privilege_file_entry != NULL, NULL);
        return privilege_file_entry->defaults;
}

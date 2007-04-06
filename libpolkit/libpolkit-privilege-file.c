/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege-file.c : privilege files
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
#include "libpolkit-privilege-file.h"

/**
 * SECTION:libpolkit-privilege-file
 * @short_description: Privileges files.
 *
 * This class is used to represent a privilege files.
 **/

/**
 * PolKitPrivilegeFile:
 *
 * Objects of this class are used to record information about a
 * privilege.
 **/
struct PolKitPrivilegeFile
{
        int refcount;
        GSList *entries;
};

/**
 * libpolkit_privilege_file_new:
 * @path: path to privilege file
 * @error: return location for error
 * 
 * Create a new #PolKitPrivilegeFile object. If the file does not
 * validate, a human readable explanation of why will be set in
 * @error.
 * 
 * Returns: the new object or #NULL if error is set
 **/
PolKitPrivilegeFile *
libpolkit_privilege_file_new (const char *path, GError **error)
{
        GKeyFile *key_file;
        PolKitPrivilegeFile *pf;
        char **groups;
        gsize groups_len;
        int n;

        pf = NULL;
        key_file = NULL;
        groups = NULL;

        if (!g_str_has_suffix (path, ".priv")) {
                g_set_error (error, 
                             POLKIT_ERROR, 
                             POLKIT_ERROR_PRIVILEGE_FILE_INVALID,
                             "Privilege files must have extension .priv");
                goto error;
        }

        key_file = g_key_file_new ();
        if (!g_key_file_load_from_file (key_file, path, G_KEY_FILE_NONE, error))
                goto error;

        pf = g_new0 (PolKitPrivilegeFile, 1);
        pf->refcount = 1;

        groups = g_key_file_get_groups(key_file, &groups_len);
        if (groups == NULL)
                goto error;

        for (n = 0; groups[n] != NULL; n++) {
                const char *privilege;
                PolKitPrivilegeFileEntry *pfe;

                if (!g_str_has_prefix (groups[n], "Privilege ")) {
                        g_set_error (error, 
                                     POLKIT_ERROR, 
                                     POLKIT_ERROR_PRIVILEGE_FILE_INVALID,
                                     "Unknown group of name '%s'", groups[n]);
                        goto error;
                }

                privilege = groups[n] + 10; /* strlen ("Privilege ") */
                if (strlen (privilege) == 0) {
                        g_set_error (error, 
                                     POLKIT_ERROR, 
                                     POLKIT_ERROR_PRIVILEGE_FILE_INVALID,
                                     "Zero-length privilege name");
                        goto error;
                }

                pfe = libpolkit_privilege_file_entry_new (key_file, privilege, error);
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
                libpolkit_privilege_file_unref (pf);
        return NULL;
}

/**
 * libpolkit_privilege_file_ref:
 * @privilege_file: the privilege file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPrivilegeFile *
libpolkit_privilege_file_ref (PolKitPrivilegeFile *privilege_file)
{
        g_return_val_if_fail (privilege_file != NULL, privilege_file);
        privilege_file->refcount++;
        return privilege_file;
}

/**
 * libpolkit_privilege_file_unref:
 * @privilege_file: the privilege file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_privilege_file_unref (PolKitPrivilegeFile *privilege_file)
{
        GSList *i;
        g_return_if_fail (privilege_file != NULL);
        privilege_file->refcount--;
        if (privilege_file->refcount > 0) 
                return;
        for (i = privilege_file->entries; i != NULL; i = g_slist_next (i)) {
                libpolkit_privilege_file_entry_unref (i->data);
        }
        if (privilege_file->entries != NULL)
                g_slist_free (privilege_file->entries);
        g_free (privilege_file);
}

/**
 * libpolkit_privilege_file_get_entries:
 * @privilege_file: the privilege file object
 * 
 * Get the entries stemming from the given file.
 * 
 * Returns: A #GSList of the entries.
 **/
GSList *
libpolkit_privilege_file_get_entries (PolKitPrivilegeFile *privilege_file)
{
        g_return_val_if_fail (privilege_file != NULL, NULL);
        return privilege_file->entries;
}


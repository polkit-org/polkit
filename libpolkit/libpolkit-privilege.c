/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege.c : privilege
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
#include "libpolkit-privilege.h"

/**
 * SECTION:libpolkit-privilege
 * @short_description: Privileges.
 *
 * This class is used to represent a privilege. TODO: describe what a privilege really is.
 **/

/**
 * PolKitPrivilege:
 *
 * Objects of this class are used to record information about a
 * privilege.
 **/
struct PolKitPrivilege
{
        int refcount;
        char *id;
};

/**
 * libpolkit_privilege_new:
 * 
 * Create a new #PolKitPrivilege object.
 * 
 * Returns: the new object
 **/
PolKitPrivilege *
libpolkit_privilege_new (void)
{
        PolKitPrivilege *privilege;
        privilege = g_new0 (PolKitPrivilege, 1);
        privilege->refcount = 1;
        return privilege;
}

/**
 * libpolkit_privilege_ref:
 * @privilege: the privilege object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPrivilege *
libpolkit_privilege_ref (PolKitPrivilege *privilege)
{
        g_return_val_if_fail (privilege != NULL, privilege);
        privilege->refcount++;
        return privilege;
}

/**
 * libpolkit_privilege_unref:
 * @privilege: the privilege object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_privilege_unref (PolKitPrivilege *privilege)
{
        g_return_if_fail (privilege != NULL);
        privilege->refcount--;
        if (privilege->refcount > 0) 
                return;
        g_free (privilege->id);
        g_free (privilege);
}

/**
 * libpolkit_privilege_set_privilege_id:
 * @privilege: the privilege object
 * @privilege_id: privilege identifier
 * 
 * Set the privilege identifier
 **/
void
libpolkit_privilege_set_privilege_id (PolKitPrivilege *privilege, const char  *privilege_id)
{
        g_return_if_fail (privilege != NULL);
        if (privilege->id != NULL)
                g_free (privilege->id);
        privilege->id = g_strdup (privilege_id);
}

/**
 * libpolkit_privilege_get_privilege_id:
 * @privilege: the privilege object
 * @out_privilege_id: Returns the privilege identifier. The caller shall not free this string.
 * 
 * Get the privilege identifier.
 * 
 * Returns: TRUE iff the value was returned.
 **/
gboolean
libpolkit_privilege_get_privilege_id (PolKitPrivilege *privilege, char **out_privilege_id)
{
        g_return_val_if_fail (privilege != NULL, FALSE);
        g_return_val_if_fail (out_privilege_id != NULL, FALSE);
        if (privilege->id == NULL)
                return FALSE;
        *out_privilege_id = privilege->id;
        return TRUE;
}

/**
 * libpolkit_privilege_debug:
 * @privilege: the object
 * 
 * Print debug details
 **/
void
libpolkit_privilege_debug (PolKitPrivilege *privilege)
{
        g_return_if_fail (privilege != NULL);
        _pk_debug ("PolKitPrivilege: refcount=%d id=%s", privilege->refcount, privilege->id);
}

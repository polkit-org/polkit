/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-resource.c : resources
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
#include "libpolkit-resource.h"
#include "libpolkit-utils.h"

/**
 * SECTION:libpolkit-resource
 * @short_description: Resources.
 *
 * This class is used to represent a resource. TODO: describe what a resource really is.
 **/

/**
 * PolKitResource:
 *
 * Objects of this class are used to record information about a
 * resource. TODO: describe what a resource really is.
 **/
struct PolKitResource
{
        int refcount;
        char *type;
        char *id;
};

/**
 * libpolkit_resource_new:
 * 
 * Create a new #PolKitResource object.
 * 
 * Returns: the new object
 **/
PolKitResource *
libpolkit_resource_new (void)
{
        PolKitResource *resource;
        resource = g_new0 (PolKitResource, 1);
        resource->refcount = 1;
        return resource;
}

/**
 * libpolkit_resource_ref:
 * @resource: the resource object
 * 
 * Increase reference count
 * 
 * Returns: the object
 **/
PolKitResource *
libpolkit_resource_ref (PolKitResource *resource)
{
        g_return_val_if_fail (resource != NULL, resource);
        resource->refcount++;
        return resource;
}


/**
 * libpolkit_resource_unref:
 * @resource: the resource object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void 
libpolkit_resource_unref (PolKitResource *resource)
{
        g_return_if_fail (resource != NULL);

        resource->refcount--;
        if (resource->refcount > 0) 
                return;

        g_free (resource->type);
        g_free (resource->id);
        g_free (resource);
}


/**
 * libpolkit_resource_set_resource_type:
 * @resource: the resource object
 * @resource_type: type of resource
 * 
 * Set the type of the resource. TODO: link to wtf this is.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
libpolkit_resource_set_resource_type (PolKitResource *resource, const char  *resource_type)
{
        g_return_val_if_fail (resource != NULL, FALSE);
        g_return_val_if_fail (_pk_validate_identifier (resource_type), FALSE);
        if (resource->type != NULL)
                g_free (resource->type);
        resource->type = g_strdup (resource_type);
        return TRUE;
}

/**
 * libpolkit_resource_set_resource_id:
 * @resource: the resource object
 * @resource_id: identifier of resource
 * 
 * set the identifier of the resource. TODO: link to wtf this is.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
libpolkit_resource_set_resource_id (PolKitResource *resource, const char  *resource_id)
{
        g_return_val_if_fail (resource != NULL, FALSE);
        g_return_val_if_fail (_pk_validate_identifier (resource_id), FALSE);
        if (resource->id != NULL)
                g_free (resource->id);
        resource->id = g_strdup (resource_id);
        return TRUE;
}

/**
 * libpolkit_resource_get_resource_type:
 * @resource: the resource object
 * @out_resource_type: Returns the resource type. The caller shall not free this string.
 * 
 * Get the type of the resource.
 * 
 * Returns: TRUE iff the value was returned.
 **/
polkit_bool_t
libpolkit_resource_get_resource_type (PolKitResource *resource, char **out_resource_type)
{
        g_return_val_if_fail (resource != NULL, FALSE);
        g_return_val_if_fail (out_resource_type != NULL, FALSE);

        if (resource->type == NULL)
                return FALSE;

        *out_resource_type = resource->type;
        return TRUE;
}

/**
 * libpolkit_resource_get_resource_id:
 * @resource: the resource object
 * @out_resource_id: Returns the resource identifier. The caller shall not free this string.
 * 
 * Get the identifier of the resource
 * 
 * Returns: TRUE iff the value was returned.
 **/
polkit_bool_t
libpolkit_resource_get_resource_id (PolKitResource *resource, char **out_resource_id)
{
        g_return_val_if_fail (resource != NULL, FALSE);
        g_return_val_if_fail (out_resource_id != NULL, FALSE);

        if (resource->id == NULL)
                return FALSE;

        *out_resource_id = resource->id;
        return TRUE;
}

/**
 * libpolkit_resource_debug:
 * @resource: the object
 * 
 * Print debug details
 **/
void
libpolkit_resource_debug (PolKitResource *resource)
{
        g_return_if_fail (resource != NULL);
        _pk_debug ("PolKitResource: refcount=%d type=%s id=%s", resource->refcount, resource->type, resource->id);
}

/**
 * libpolkit_resource_validate:
 * @resource: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 **/
polkit_bool_t
libpolkit_resource_validate (PolKitResource *resource)
{
        g_return_val_if_fail (resource != NULL, FALSE);
        g_return_val_if_fail (resource->type != NULL, FALSE);
        g_return_val_if_fail (resource->id != NULL, FALSE);
        return TRUE;
}

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
#include "libpolkit-resource.h"

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
        return NULL;
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
        return resource;
}

/**
 * libpolkit_resource_set_resource_type:
 * @resource: the resource object
 * @resource_type: type of resource
 * 
 * Set the type of the resource. TODO: link to wtf this is.
 **/
void
libpolkit_resource_set_resource_type (PolKitResource *resource, const char  *resource_type)
{
}

/**
 * libpolkit_resource_set_resource_id:
 * @resource: the resource object
 * @resource_id: identifier of resource
 * 
 * set the identifier of the resource. TODO: link to wtf this is.
 **/
void
libpolkit_resource_set_resource_id (PolKitResource *resource, const char  *resource_id)
{
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
gboolean
libpolkit_resource_get_resource_type (PolKitResource *resource, char **out_resource_type)
{
        return FALSE;
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
gboolean 
libpolkit_resource_get_resource_id (PolKitResource *resource, char **out_resource_id)
{
        return FALSE;
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
}

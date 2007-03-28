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

struct PolKitResource_s
{
};

PolKitResource *
libpolkit_resource_new (void)
{
        return NULL;
}

PolKitResource *
libpolkit_resource_ref (PolKitResource *resource)
{
        return resource;
}

void
libpolkit_resource_set_resource_type (PolKitResource *resource, const char  *resource_type)
{
}

void
libpolkit_resource_set_resource_id (PolKitResource *resource, const char  *resource_id)
{
}

gboolean
libpolkit_resource_get_resource_type (PolKitResource *resource, char **out_resource_type)
{
        return FALSE;
}

gboolean 
libpolkit_resource_get_resource_id (PolKitResource *resource, char **out_resource_id)
{
        return FALSE;
}

void 
libpolkit_resource_unref (PolKitResource *resource)
{
}

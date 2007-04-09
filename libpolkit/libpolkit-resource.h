/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-resource.h : resources
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBPOLKIT_RESOURCE_H
#define LIBPOLKIT_RESOURCE_H

#include <stdbool.h>

struct PolKitResource;
typedef struct PolKitResource PolKitResource;

PolKitResource *libpolkit_resource_new               (void);
PolKitResource *libpolkit_resource_ref               (PolKitResource *resource);
void            libpolkit_resource_unref             (PolKitResource *resource);
void            libpolkit_resource_set_resource_type (PolKitResource *resource, const char  *resource_type);
void            libpolkit_resource_set_resource_id   (PolKitResource *resource, const char  *resource_id);
bool            libpolkit_resource_get_resource_type (PolKitResource *resource, char       **out_resource_type);
bool            libpolkit_resource_get_resource_id   (PolKitResource *resource, char       **out_resource_id);

void            libpolkit_resource_debug             (PolKitResource *resource);

#endif /* LIBPOLKIT_RESOURCE_H */



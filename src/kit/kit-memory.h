/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-memory.h : Memory management
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

#if !defined (KIT_COMPILATION) && !defined(_KIT_INSIDE_KIT_H)
#error "Only <kit/kit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef KIT_MEMORY_H
#define KIT_MEMORY_H

#include <stdarg.h>
#include <stdlib.h>
#include <kit/kit.h>

KIT_BEGIN_DECLS

void *kit_malloc  (size_t bytes);
void *kit_malloc0 (size_t bytes);
void *kit_realloc (void *memory, size_t bytes);
void  kit_free    (void *memory);

/**
 * kit_new:
 * @type: the type of object to allocate
 * @count: number of objects to allocate
 *
 * Allocate memory for @count structures of type @type.
 *
 * Returns: Allocated memory, cast to a pointer of #type or #NULL on OOM.
 */
#define kit_new(type, count)  ((type*)kit_malloc (sizeof (type) * (count)));

/**
 * kit_new0:
 * @type: the type of object to allocate
 * @count: number of objects to allocate
 *
 * Allocate zeroed memory for @count structures of type @type.
 *
 * Returns: Allocated memory, cast to a pointer of #type or #NULL on OOM.
 */
#define kit_new0(type, count) ((type*)kit_malloc0 (sizeof (type) * (count)));

void  _kit_memory_reset (void);
int   _kit_memory_get_current_allocations (void);
int   _kit_memory_get_total_allocations (void);
void  _kit_memory_fail_nth_alloc (int number);

KIT_END_DECLS

#endif /* KIT_MEMORY_H */



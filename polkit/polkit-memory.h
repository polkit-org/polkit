/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-memory.h : Memory management
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_MEMORY_H
#define POLKIT_MEMORY_H

#include <stdarg.h>
#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

void *p_malloc  (size_t bytes);
void *p_malloc0 (size_t bytes);
void  p_free    (void *memory);

/**
 * p_new:
 * @type: the type of object to allocate
 * @count: number of objects to allocate
 *
 * Allocate memory for @count structures of type @type.
 *
 * Returns: Allocated memory, cast to a pointer of #type or #NULL on OOM.
 */
#define p_new(type, count)  ((type*)p_malloc (sizeof (type) * (count)));

/**
 * p_new0:
 * @type: the type of object to allocate
 * @count: number of objects to allocate
 *
 * Allocate zeroed memory for @count structures of type @type.
 *
 * Returns: Allocated memory, cast to a pointer of #type or #NULL on OOM.
 */
#define p_new0(type, count) ((type*)p_malloc0 (sizeof (type) * (count)));

char *p_strdup         (const char *s);
char *p_strndup        (const char *s, size_t n);
char* p_strdup_printf  (const char *format, ...);
char* p_strdup_vprintf (const char *format, va_list args);


POLKIT_END_DECLS

#endif /* POLKIT_MEMORY_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-memory.h : Memory management
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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
void  _kit_memory_print_outstanding_allocations (void);

KIT_END_DECLS

#endif /* KIT_MEMORY_H */



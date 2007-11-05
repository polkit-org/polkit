/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-memory.c : Memory management
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include <polkit/polkit-memory.h>
#include <polkit/polkit-private.h>

/**
 * SECTION:polkit-memory
 * @title: Memory management
 * @short_description: Memory management
 *
 * Functions used for memory management.
 *
 * Since: 0.7
 **/


#ifdef POLKIT_BUILD_TESTS

static int _cur_allocs = 0;
static int _total_allocs = 0;
static int _fail_nth = -1;

void 
_polkit_memory_reset (void)
{
        _cur_allocs = 0;
        _total_allocs = 0;
        _fail_nth = -1;
}

int 
_polkit_memory_get_current_allocations (void)
{
        return _cur_allocs;
}

int 
_polkit_memory_get_total_allocations (void)
{
        return _total_allocs;
}

void 
_polkit_memory_fail_nth_alloc (int number)
{
        _fail_nth = number;
}

/**
 * p_malloc:
 * @bytes: number of 8-bit bytes to allocate
 *
 * Allocate memory
 *
 * Returns: memory location or #NULL on OOM. Free with p_free().
 *
 * Since: 0.7
 */
void *
p_malloc (size_t bytes)
{
        void *p;

        if (_fail_nth != -1 && _total_allocs == _fail_nth) {
                return NULL;
        }

        p = malloc (bytes);

        if (p != NULL)  {
                _cur_allocs++;
                _total_allocs++;
        }

        return p;
}

/**
 * p_malloc0:
 * @bytes: number of 8-bit bytes to allocate
 *
 * Allocate memory and zero it.
 *
 * Returns: memory location or #NULL on OOM. Free with p_free().
 *
 * Since: 0.7
 */
void *
p_malloc0 (size_t bytes)
{
        void *p;

        if (_fail_nth != -1 && _total_allocs == _fail_nth) {
                return NULL;
        }

        p = calloc (1, bytes);

        if (p != NULL)  {
                _cur_allocs++;
                _total_allocs++;
        }

        return p;
}

/**
 * p_free:
 * @memory: pointer to memory allocated with p_malloc() + friends
 *
 * Free memory allocated by p_malloc() + friends.
 *
 * Since: 0.7
 */
void
p_free (void *memory)
{
        free (memory);
        if (memory != NULL) {
                _cur_allocs--;
        }
}

/**
 * p_strdup:
 * @s: string
 *
 * Duplicate a string. Similar to strdup(3).
 *
 * Returns: Allocated memory or #NULL on OOM. Free with p_free().
 *
 * Since: 0.7
 */
char *
p_strdup (const char *s)
{
        void *p;
        size_t len;

        len = strlen (s) + 1;

        p = p_malloc (len + 1);
        if (p == NULL)
                goto out;

        memcpy (p, s, len + 1);

out:
        return p;
}

/*--------------------------------------------------------------------------------------------------------------*/
#else
/*--------------------------------------------------------------------------------------------------------------*/

void *
p_malloc (size_t bytes)
{
        return malloc (bytes);
}

void *
p_malloc0 (size_t bytes)
{
        return calloc (1, bytes);
}

void
p_free (void *memory)
{
        free (memory);
}

void 
_polkit_memory_reset (void)
{
}

int 
_polkit_memory_get_current_allocations (void)
{
        return -1;
}

int 
_polkit_memory_get_total_allocations (void)
{
        return -1;
}

void 
_polkit_memory_fail_nth_alloc (int number)
{
}

char *
p_strdup (const char *s)
{
        return strdup (s);
}

#endif /* POLKIT_BUILD_TESTS */

/**
 * p_strdup_printf:
 * @format: sprintf(3) format string
 * @...:  the parameters to insert into the format string.
 * 
 * Similar to the standard C sprintf(3) function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed when no longer
 * needed.
 *
 * Returns: A newly allocated string or #NULL on OOM. Free with p_free().
 *
 * Since: 0.7
 */
char* 
p_strdup_printf (const char *format, ...)
{
        char *s;
        va_list args;

        va_start (args, format);
        s = p_strdup_vprintf (format, args);
        va_end (args);

        return s;
}

/**
 * p_strdup_vprintf:
 * @format: printf(3) format string
 * @args: list of parameters to insert
 * 
 * Similar to the standard C vsprintf(3) function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed when no longer
 * needed.
 *
 * Returns: A newly allocated string or #NULL on OOM. Free with p_free().
 *
 * Since: 0.7
 */
char* 
p_strdup_vprintf (const char *format, va_list args)
{
        char *s;
        char *gs;
        /* TODO: reimplement */
        gs = g_strdup_vprintf (format, args);
        s = p_strdup (gs);
        g_free (gs);

        return s;
}

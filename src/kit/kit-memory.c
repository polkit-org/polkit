/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-memory.c : Memory management
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef BUILT_R_DYNAMIC
#include <execinfo.h>
#endif

#include <kit/kit-memory.h>
#include <kit/kit-test.h>

/**
 * SECTION:kit-memory
 * @title: Memory management
 * @short_description: Memory management
 *
 * Functions used for memory management.
 **/

#ifdef KIT_BUILD_TESTS

static int _cur_allocs = 0;
static int _total_allocs = 0;
static int _fail_nth = -1;


#if defined(KIT_BUILD_TESTS) && defined(BUILT_R_DYNAMIC)
typedef struct _KitAllocationEntry {
        const void *memory;
        void *backtrace[100];
        int backtrace_size;
        struct _KitAllocationEntry *next;
} KitAllocationEntry;

static KitAllocationEntry *alloc_list_head = NULL;
#endif

void 
_kit_memory_reset (void)
{
        _cur_allocs = 0;
        _total_allocs = 0;
        _fail_nth = -1;

#if defined(KIT_BUILD_TESTS) && defined(BUILT_R_DYNAMIC)
        /* TODO: free existing allocs */
        alloc_list_head = NULL;
#endif
}

int 
_kit_memory_get_current_allocations (void)
{
        return _cur_allocs;
}

int 
_kit_memory_get_total_allocations (void)
{
        return _total_allocs;
}

void 
_kit_memory_fail_nth_alloc (int number)
{
        _fail_nth = number;
}

static inline void
_alloc_add (const void *memory)
{
#if defined(KIT_BUILD_TESTS) && defined(BUILT_R_DYNAMIC)
        KitAllocationEntry *entry;

        entry = malloc (sizeof (KitAllocationEntry));
        entry->memory = memory;
        entry->backtrace_size = backtrace (entry->backtrace, 100);
        entry->next = alloc_list_head;

        alloc_list_head = entry;
#endif
}

static inline void
_alloc_remove (const void *memory)
{
#if defined(KIT_BUILD_TESTS) && defined(BUILT_R_DYNAMIC)
        KitAllocationEntry *l;
        KitAllocationEntry **prev;

        prev = &alloc_list_head;
        for (l = alloc_list_head; l != NULL; l = l->next) {
                if (l->memory == memory) {
                        *prev = l->next;
                        free (l);
                        break;
                }

                prev = &(l->next);
        }
#endif
}

void
_kit_memory_print_outstanding_allocations (void)
{
#if defined(KIT_BUILD_TESTS) && defined(BUILT_R_DYNAMIC)
        KitAllocationEntry *l;
        for (l = alloc_list_head; l != NULL; l = l->next) {
                int i;
                char **syms;

                syms = backtrace_symbols (l->backtrace, l->backtrace_size);

                i = 0;
                while (i < l->backtrace_size)
                {
                        fprintf (stderr, "  %s\n", syms[i]);
                        ++i;
                }
                fprintf (stderr, "\n");
                fflush (stderr);

                free (syms);
        }
#endif
}


/**
 * kit_malloc:
 * @bytes: number of 8-bit bytes to allocate
 *
 * Allocate memory
 *
 * Returns: memory location or #NULL on OOM. Free with kit_free().
 */
void *
kit_malloc (size_t bytes)
{
        void *p;

        if (_fail_nth != -1 && _total_allocs == _fail_nth) {
                errno = ENOMEM;
                _total_allocs++;

                //fprintf (stderr, "  Failing alloc @\n");
                //kit_print_backtrace ();

                return NULL;
        }

        p = malloc (bytes);

        if (p != NULL)  {
                _cur_allocs++;
                _total_allocs++;
                _alloc_add (p);
        }

        return p;
}

/**
 * kit_malloc0:
 * @bytes: number of 8-bit bytes to allocate
 *
 * Allocate memory and zero it.
 *
 * Returns: memory location or #NULL on OOM. Free with kit_free().
 */
void *
kit_malloc0 (size_t bytes)
{
        void *p;

        if (_fail_nth != -1 && _total_allocs == _fail_nth) {
                errno = ENOMEM;
                return NULL;
        }

        p = calloc (1, bytes);

        if (p != NULL)  {
                _cur_allocs++;
                _total_allocs++;
                _alloc_add (p);
        }

        return p;
}

/**
 * kit_realloc:
 * @memory: memory previously allocated
 * @bytes: new size
 *
 * Reallocate memory; like realloc(3).
 *
 * Returns: memory location or #NULL on OOM. Free with kit_free().
 */
void *
kit_realloc (void *memory, size_t bytes)
{
        void *p;

        if (memory == NULL)
                return kit_malloc (bytes);

        if (bytes == 0) {
                kit_free (memory);
                return memory;
        }

        if (_fail_nth != -1 && _total_allocs == _fail_nth) {
                errno = ENOMEM;
                return NULL;
        }

        _alloc_remove (p);
        p = realloc (memory, bytes);
        if (p != NULL)
                _alloc_add (p);

        return p;
}

/**
 * kit_free:
 * @memory: pointer to memory allocated with kit_malloc() + friends
 *
 * Free memory allocated by kit_malloc() + friends.
 */
void
kit_free (void *memory)
{
        free (memory);
        if (memory != NULL) {
                _alloc_remove (memory);
                _cur_allocs--;
        }
}

/*--------------------------------------------------------------------------------------------------------------*/
#else
/*--------------------------------------------------------------------------------------------------------------*/

void *
kit_malloc (size_t bytes)
{
        return malloc (bytes);
}

void *
kit_malloc0 (size_t bytes)
{
        return calloc (1, bytes);
}

void *
kit_realloc (void *memory, size_t bytes)
{
        return realloc (memory, bytes);
}

void
kit_free (void *memory)
{
        free (memory);
}

void 
_kit_memory_reset (void)
{
}

int 
_kit_memory_get_current_allocations (void)
{
        return -1;
}

int 
_kit_memory_get_total_allocations (void)
{
        return -1;
}

void 
_kit_memory_fail_nth_alloc (int number)
{
}

void
_kit_memory_print_outstanding_allocations (void)
{
}

#endif /* KIT_BUILD_TESTS */

/* There's probably a better place for this function ... */

/**
 * kit_print_backtrace:
 *
 * Print a back trace if built with -rdynamic or similar.
 */
void 
kit_print_backtrace (void)
{
#ifdef BUILT_R_DYNAMIC
        void *bt[500];
        int bt_size;
        int i;
        char **syms;
        
        bt_size = backtrace (bt, 500);
        
        syms = backtrace_symbols (bt, bt_size);
        
        i = 0;
        while (i < bt_size)
        {
                fprintf (stderr, "  %s\n", syms[i]);
                ++i;
        }
        fprintf (stderr, "\n");
        fflush (stderr);

        free (syms);
#else
        fprintf (stderr, " Not built with -rdynamic so unable to print a backtrace\n");
#endif
}




#ifdef KIT_BUILD_TESTS

static kit_bool_t
_run_test (void)
{
        int n;
        char *p;
        char *p2;

        if ((p = kit_malloc (1000)) != NULL) {
                for (n = 0; n < 1000; n++)
                        p[n] = n;

                p2 = kit_realloc (p, 2000);
                if (p2 != NULL) {
                        p = p2;

                        for (n = 0; n < 2000; n++)
                                p[n] = n;
                }

                kit_free (p);
        }

        if ((p = kit_realloc (NULL, 1000)) != NULL) {
                for (n = 0; n < 1000; n++)
                        p[n] = n;

                kit_realloc (p, 0);
        }

        if ((p = kit_malloc0 (1000)) != NULL) {
                for (n = 0; n < 1000; n++)
                        kit_assert (p[n] == '\0');
                kit_free (p);
        }
        
        return TRUE;
}

KitTest _test_memory = {
        "kit_memory",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-test.c : PolicyKit test
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

#include <stdio.h>
#include <stdlib.h>
#include <kit/kit-test.h>
#include <kit/kit-memory.h>

#define MAX_TESTS 64

/**
 * SECTION:kit-test
 * @short_description: Testing code for libkit
 *
 * Testing code for libkit.
 */

static KitTest *tests[] = {
        &_test_message,
        &_test_memory,
        &_test_string,
        &_test_list,
        &_test_hash,
        &_test_file,
        &_test_spawn,
};

int 
main (int argc, char *argv[])
{
        int ret;
        int n;
        int num_tests;

        ret = 0;

        num_tests = sizeof (tests) / sizeof (KitTest*);

        printf ("Running %d unit tests\n", num_tests);
        for (n = 0; n < num_tests; n++) {
                int m;
                int total_allocs;
                int delta;
                KitTest *test = tests[n];

                _kit_memory_reset ();

                if (test->setup != NULL)
                        test->setup ();

                printf ("Running: %s\n", test->name);
                if (!test->run ()) {
                        printf ("Failed\n");
                        ret = 1;
                        goto test_done;
                }

                total_allocs = _kit_memory_get_total_allocations ();
                printf ("  Unit test made %d allocations in total\n", total_allocs);
                
                delta = _kit_memory_get_current_allocations ();
                if (delta != 0) {
                        printf ("  Unit test leaked %d allocations\n", delta);
                        ret = 1;
                }
                
                for (m = 0; m < total_allocs; m++) {
                        printf ("  Failing allocation %d of %d\n", m + 1, total_allocs);
                        
                        _kit_memory_reset ();
                        _kit_memory_fail_nth_alloc (m);
                        
                        if (!test->run ()) {
                                printf ("  Failed\n");
                                ret = 1;
                                continue;
                        }
                        
                        delta = _kit_memory_get_current_allocations ();
                        if (delta != 0) {
                                printf ("  Unit test leaked %d allocations\n", delta);
                                ret = 1;
                        }
                }

        test_done:
                if (test->teardown != NULL)
                        test->teardown ();
        }

        return ret;
}

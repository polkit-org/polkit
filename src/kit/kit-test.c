/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-test.c : PolicyKit test
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

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SOLARIS
#include <sys/types.h>
#endif
#include <kit/kit-test.h>
#include <kit/kit-memory.h>

/**
 * SECTION:kit-test
 * @title: Unit testing
 * @short_description: Unit testing
 *
 * Functions used for unit testing.
 */

/**
 * kit_test_run:
 * @tests: array of #KitTest objects
 * @num_tests: size of @tests array
 *
 * Runs a number of tests simulating Out Of Memory. Checks for both
 * memory and file descriptor leaks. 
 *
 * This function is only available if libkit have been built with
 * KIT_BUILD_TESTS.
 *
 * Returns: %TRUE only if all tests succeed without memory or file descriptor leaks
 */
kit_bool_t
kit_test_run (KitTest **tests, size_t num_tests)
{
        kit_bool_t ret;
        unsigned int n;

        /* be optimistic! */
        ret = TRUE;

        printf ("Running %d unit tests\n", num_tests);
        for (n = 0; n < num_tests; n++) {
                int m;
                int total_allocs;
                int delta;
                int num_fd;
                int num_fd_after;
                KitTest *test = tests[n];

                _kit_memory_reset ();

                if (test->setup != NULL)
                        test->setup ();

                num_fd = _kit_get_num_fd ();
                printf ("Running: %s\n", test->name);
                if (!test->run ()) {
                        printf ("Failed\n");
                        ret = FALSE;
                        goto test_done;
                }
                num_fd_after = _kit_get_num_fd ();

                total_allocs = _kit_memory_get_total_allocations ();
                printf ("  Unit test made %d allocations in total\n", total_allocs);
                
                delta = _kit_memory_get_current_allocations ();
                if (delta != 0) {
                        printf ("  Unit test leaked %d allocations\n", delta);
                        ret = FALSE;
                }
                if (num_fd != num_fd_after) {
                        printf ("  Unit test leaked %d file descriptors\n", num_fd_after - num_fd);
                        ret = FALSE;
                }
                
                for (m = 0; m < total_allocs; m++) {
                        printf ("  Failing allocation %d of %d\n", m + 1, total_allocs);
                        
                        _kit_memory_reset ();
                        _kit_memory_fail_nth_alloc (m);

                        num_fd = _kit_get_num_fd ();
                        if (!test->run ()) {
                                printf ("  Failed\n");
                                ret = FALSE;
                                continue;
                        }
                        num_fd_after = _kit_get_num_fd ();
                        
                        delta = _kit_memory_get_current_allocations ();
                        if (delta != 0) {
                                printf ("  Unit test leaked %d allocations\n", delta);
                                ret = FALSE;
                        }
                        if (num_fd != num_fd_after) {
                                printf ("  Unit test leaked %d file descriptors\n", num_fd_after - num_fd);
                                ret = FALSE;
                        }

                }

        test_done:
                if (test->teardown != NULL)
                        test->teardown ();
        }

        return ret;
}

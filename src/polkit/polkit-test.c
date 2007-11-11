/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-test.c : PolicyKit test
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
#include <syslog.h>
#include <polkit/polkit-test.h>
#include <polkit/polkit-private.h>
#include <polkit/polkit-private.h>

#define MAX_TESTS 64

/**
 * SECTION:polkit-test
 * @short_description: Testing code for libpolkit
 *
 * Testing code for libpolkit.
 */

static PolKitTest *tests[] = {
        &_test_action,
        &_test_error,
        &_test_result,
        &_test_seat,
        &_test_session,
        &_test_caller,
        &_test_policy_default,
        &_test_policy_file_entry,
        &_test_policy_file,
        &_test_policy_cache,
        &_test_authorization_constraint,
        &_test_authorization,
        &_test_authorization_db,
        &_test_config,
        &_test_sysdeps,
        &_test_context,
};

int 
main (int argc, char *argv[])
{
        int ret;
        int n;
        int num_tests;

        ret = 0;

        num_tests = sizeof (tests) / sizeof (PolKitTest*);

        /* Some of the code will log to syslog because .policy files
         * etc. may be malformed. Since this will open a socket to the
         * system logger preempt this so the fd-leak checking don't
         * freak out.
         */
        syslog (LOG_INFO, "libpolkit: initiating test; bogus alerts may be written to syslog");

        printf ("Running %d unit tests\n", num_tests);
        for (n = 0; n < num_tests; n++) {
                int m;
                int total_allocs;
                int delta;
                int num_fd;
                int num_fd_after;
                PolKitTest *test = tests[n];

                _kit_memory_reset ();

                if (test->setup != NULL)
                        test->setup ();

                num_fd = _kit_get_num_fd ();
                printf ("Running: %s\n", test->name);
                if (!test->run ()) {
                        printf ("Failed\n");
                        ret = 1;
                        goto test_done;
                }
                num_fd_after = _kit_get_num_fd ();

                total_allocs = _kit_memory_get_total_allocations ();
                printf ("  Unit test made %d allocations in total\n", total_allocs);
                
                delta = _kit_memory_get_current_allocations ();
                if (delta != 0) {
                        printf ("  Unit test leaked %d allocations\n", delta);
                        ret = 1;
                }
                if (num_fd != num_fd_after) {
                        printf ("  Unit test leaked %d file descriptors\n", num_fd_after - num_fd);
                        ret = 1;
                }
                
                for (m = 0; m < total_allocs; m++) {
                        printf ("  Failing allocation %d of %d\n", m + 1, total_allocs);
                        
                        _kit_memory_reset ();
                        _kit_memory_fail_nth_alloc (m);
                        
                        num_fd = _kit_get_num_fd ();
                        if (!test->run ()) {
                                printf ("  Failed\n");
                                ret = 1;
                                continue;
                        }
                        num_fd_after = _kit_get_num_fd ();
                        
                        delta = _kit_memory_get_current_allocations ();
                        if (delta != 0) {
                                printf ("  Unit test leaked %d allocations\n", delta);
                                ret = 1;
                        }
                        if (num_fd != num_fd_after) {
                                printf ("  Unit test leaked %d file descriptors\n", num_fd_after - num_fd);
                                ret = 1;
                        }
                }

        test_done:
                if (test->teardown != NULL)
                        test->teardown ();
        }

        return ret;
}

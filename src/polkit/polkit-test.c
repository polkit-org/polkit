/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-test.c : PolicyKit test
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

static KitTest *tests[] = {
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
        &_test_utils,
        &_test_context,
};

int 
main (int argc, char *argv[])
{
        /* Some of the code will log to syslog because .policy files
         * etc. may be malformed. Since this will open a socket to the
         * system logger preempt this so the fd-leak checking don't
         * freak out.
         */
        syslog (LOG_INFO, "libpolkit: initiating test; bogus alerts may be written to syslog");

        if (kit_test_run (tests, sizeof (tests) / sizeof (KitTest*)))
                return 0;
        else
                return 1;
}

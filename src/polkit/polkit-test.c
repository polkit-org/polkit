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

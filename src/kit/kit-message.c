/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-message.c : Message utilities
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <kit/kit.h>
#include "kit-test.h"

/**
 * SECTION:kit-message
 * @title: Message utilities
 * @short_description: Message utilities
 *
 * Various message and logging utilities.
 **/

/**
 * kit_debug:
 * @format: printf(3) style format string
 * @...: the parameters to insert into @format
 *
 * Outputs a debug message on stdout.
 */
void 
kit_debug (const char *format, ...)
{
        va_list args;
        char buf[1024];

        kit_return_if_fail (format != NULL);

        va_start (args, format);
        vsnprintf (buf, sizeof (buf), format, args);
        va_end (args);

        printf ("[INFO %5d] %s\n", getpid (), buf);
}

/**
 * kit_warning:
 * @format: printf(3) style format string
 * @...: the parameters to insert into @format
 *
 * Outputs a warning message on stderr.
 */
void 
kit_warning (const char *format, ...)
{
        va_list args;
        char buf[1024];

        kit_return_if_fail (format != NULL);

        va_start (args, format);
        vsnprintf (buf, sizeof (buf), format, args);
        va_end (args);

        fprintf (stderr, "[WARN %5d] %s\n", getpid (), buf);
}

#ifdef KIT_BUILD_TESTS

static kit_bool_t
_run_test (void)
{
        kit_debug ("Debug %d", 42);
        kit_warning ("Warning %d %s", 42, "foo");
        return TRUE;
}

KitTest _test_message = {
        "kit_message",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

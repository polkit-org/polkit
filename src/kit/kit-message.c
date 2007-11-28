/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-message.c : Message utilities
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

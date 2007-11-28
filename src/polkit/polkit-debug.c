/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit.c : library for querying system-wide policy
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

/**
 * SECTION:polkit-debug
 * @short_description: Internal debug functions for polkit.
 *
 * These functions are used for debug purposes
 **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "polkit-types.h"
#include "polkit-debug.h"

/**
 * pk_debug:
 * @format: format
 * 
 * Print debug message
 **/
void 
_pk_debug (const char *format, ...)
{
        va_list args;
        static polkit_bool_t show_debug = FALSE;
        static polkit_bool_t init = FALSE;

        if (!init) {
                init = TRUE;
                if (getenv ("POLKIT_DEBUG") != NULL) {
                        show_debug = TRUE;
                }
        }

        if (show_debug) {
                struct timeval tnow;
                struct tm *tlocaltime;
                struct timezone tzone;
                char tbuf[256];
                gettimeofday (&tnow, &tzone);
                tlocaltime = localtime ((time_t *) &tnow.tv_sec);
                strftime (tbuf, sizeof (tbuf), "%H:%M:%S", tlocaltime);
		fprintf (stdout, "%s.%03d: ", tbuf, (int)(tnow.tv_usec/1000));

                va_start (args, format);
                vfprintf (stdout, format, args);
                va_end (args);
                fprintf (stdout, "\n");
        }
}

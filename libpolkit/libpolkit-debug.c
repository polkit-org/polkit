/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit.c : library for querying system-wide policy
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

/**
 * SECTION:libpolkit-debug
 * @short_description: Debug functions.
 *
 * These functions are used for debug purposes
 **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "libpolkit-debug.h"

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
        static bool show_debug = false;
        static bool init = false;

        if (!init) {
                init = true;
                if (getenv ("POLKIT_DEBUG") != NULL) {
                        show_debug = true;
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

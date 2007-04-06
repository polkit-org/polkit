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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

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
        static gboolean show_debug = FALSE;
        static gboolean init = FALSE;

        if (!init) {
                init = TRUE;
                if (getenv ("POLKIT_DEBUG") != NULL) {
                        show_debug = TRUE;
                }
        }

        if (show_debug) {
                va_start (args, format);
                vfprintf (stdout, format, args);
                va_end (args);
                fprintf (stdout, "\n");
        }
}

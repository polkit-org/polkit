/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-error.c : GError error codes from PolicyKit
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
 * SECTION:polkit-error
 * @title: Error reporting
 * @short_description: Representation of recoverable errors.
 *
 * Error codes from PolicyKit.
 **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include "polkit-types.h"
#include "polkit-error.h"
#include "polkit-debug.h"

/**
 * PolKitError:
 *
 * Objects of this class are used for error reporting.
 **/
struct _PolKitError
{
        polkit_bool_t is_static;
        PolKitErrorCode error_code;
        char *error_message;
};

//static PolKitError _oom_error = {true, POLKIT_ERROR_OUT_OF_MEMORY, "Out of memory"};

/**
 * polkit_error_get_error_code:
 * @error: the error object
 * 
 * Returns the error code.
 * 
 * Returns: A value from the #PolKitErrorCode enumeration.
 **/
PolKitErrorCode 
polkit_error_get_error_code (PolKitError *error)
{
        g_return_val_if_fail (error != NULL, -1);
        return error->error_code;
}

/**
 * polkit_error_get_error_message:
 * @error: the error object
 * 
 * Get the error message.
 * 
 * Returns: A string describing the error. Caller shall not free this string.
 **/
const char *
polkit_error_get_error_message (PolKitError *error)
{
        g_return_val_if_fail (error != NULL, NULL);
        return error->error_message;
}

/**
 * polkit_error_free:
 * @error: the error
 * 
 * Free an error.
 **/
void
polkit_error_free (PolKitError *error)
{
        g_return_if_fail (error != NULL);
        if (!error->is_static) {
                g_free (error->error_message);
                g_free (error);
        }
}

/**
 * polkit_error_set_error:
 * @error: the error object
 * @error_code: A value from the #PolKitErrorCode enumeration.
 * @format: printf style formatting string
 * @Varargs: printf style arguments
 * 
 * Sets an error. If OOM, the error will be set to a pre-allocated OOM error.
 **/
void
polkit_error_set_error (PolKitError **error, PolKitErrorCode error_code, const char *format, ...)
{
        va_list args;
        PolKitError *e;

        if (error == NULL)
                return;

        e = g_new0 (PolKitError, 1);
        e->is_static = FALSE;
        e->error_code = error_code;
        va_start (args, format);
        e->error_message = g_strdup_vprintf (format, args);
        va_end (args);

        *error = e;
}

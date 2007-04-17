/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-utils.c : internal utilities used in polkit
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <glib.h>
#include <string.h>

#include "polkit-utils.h"
#include "polkit-debug.h"

/**
 * SECTION:polkit-utils
 * @short_description: Internal utility functions for polkit.
 *
 * Internal utility functions for polkit.
 **/

/**
 * _pk_validate_identifier:
 * @identifier: the NUL-terminated string to validate
 * 
 * Validates strings used for an identifier; PolicyKit conventions
 * state that identifiers must be NUL-terminated ASCII strings less
 * than 256 bytes and only contain the characters "[a-z][A-Z]0-9]._-:/"
 * 
 * Returns: #TRUE iff the identifier validates
 **/
polkit_bool_t 
_pk_validate_identifier (const char *identifier)
{
        unsigned int n;
        polkit_bool_t ret;

        g_return_val_if_fail (identifier != NULL, FALSE);

        ret = FALSE;
        for (n = 0; identifier[n] != '\0'; n++) {
                char c = identifier[n];

                if (n >= 255) {
                        _pk_debug ("identifier too long");
                        goto out;
                }

                if ((c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') ||
                    c == '.' || 
                    c == '_' || 
                    c == '-' || 
                    c == ':' || 
                    c == '/')
                        continue;

                _pk_debug ("invalid character in identifier");
                goto out;
        }

        ret = TRUE;
out:
        return ret;
}


/* Determine wether the given character is valid as a second or later character in a bus name */
#define VALID_BUS_NAME_CHARACTER(c)                 \
  ( ((c) >= '0' && (c) <= '9') ||               \
    ((c) >= 'A' && (c) <= 'Z') ||               \
    ((c) >= 'a' && (c) <= 'z') ||               \
    ((c) == '_') || ((c) == '-'))

polkit_bool_t
_pk_validate_unique_bus_name (const char *unique_bus_name)
{
        int len;
        const char *s;
        const char *end;
        const char *last_dot;
        polkit_bool_t ret;

        ret = FALSE;

        if (unique_bus_name == NULL)
                goto error;

        len = strlen (unique_bus_name);
        if (len == 0)
                goto error;

        end = unique_bus_name + len;
        last_dot = NULL;

        s = unique_bus_name;

        /* check special cases of first char so it doesn't have to be done
         * in the loop. Note we know len > 0
         */
        if (*s == ':') {
                /* unique name */
                ++s;
                while (s != end) {
                        if (*s == '.') {
                                if (G_UNLIKELY ((s + 1) == end))
                                        goto error;
                                if (G_UNLIKELY (!VALID_BUS_NAME_CHARACTER (*(s + 1))))
                                        goto error;
                                ++s; /* we just validated the next char, so skip two */
                        } else if (G_UNLIKELY (!VALID_BUS_NAME_CHARACTER (*s))) {
                                goto error;
                        }
                        ++s;
                }
        } else {
                goto error;
        }

        ret = TRUE;

error:
        if (!ret)
                _pk_debug ("name '%s' did not validate", unique_bus_name);
        return ret;
}

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-utils.c : internal utilities used in polkit
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

#include "polkit-utils.h"
#include "polkit-debug.h"
#include "polkit-private.h"
#include "polkit-test.h"

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

        kit_return_val_if_fail (identifier != NULL, FALSE);

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
                                if ((s + 1) == end)
                                        goto error;
                                if (!VALID_BUS_NAME_CHARACTER (*(s + 1)))
                                        goto error;
                                ++s; /* we just validated the next char, so skip two */
                        } else if (!VALID_BUS_NAME_CHARACTER (*s)) {
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

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_utils = {
        "polkit_utils",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

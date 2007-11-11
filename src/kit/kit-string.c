/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-string.c : String utilities
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
#include <kit/kit.h>
#include "kit-test.h"


/**
 * SECTION:kit-string
 * @title: String utilities
 * @short_description: String utilities
 *
 * Various string utilities.
 **/

#ifdef KIT_BUILD_TESTS

/**
 * kit_strdup:
 * @s: string
 *
 * Duplicate a string. Similar to strdup(3).
 *
 * Returns: Allocated memory or #NULL on OOM. Free with kit_free().
 */
char *
kit_strdup (const char *s)
{
        char *p;
        size_t len;

        len = strlen (s);

        p = kit_malloc (len + 1);
        if (p == NULL)
                goto out;

        memcpy (p, s, len);
        p[len] = '\0';

out:
        return p;
}

/**
 * kit_strndup:
 * @s: string
 * @n: size
 *
 * Duplicate a string but copy at most @n characters. If @s is longer
 * than @n, only @n characters are copied, and a terminating null byte
 * is added. Similar to strndup(3).
 *
 * Returns: Allocated memory or #NULL on OOM. Free with kit_free().
 */
char *
kit_strndup (const char *s, size_t n)
{
        char *p;
        size_t len;

        for (len = 0; len < n; len++) {
                if (s[len] == '\0')
                        break;
        }


        p = kit_malloc (len + 1);
        if (p == NULL)
                goto out;

        memcpy (p, s, len);
        p[len] = '\0';
out:
        return p;
}

#else

char *
kit_strdup (const char *s)
{
        return strdup (s);
}

char *
kit_strndup (const char *s, size_t n)
{
        return strndup (s, n);
}

#endif /* KIT_BUILD_TESTS */

/**
 * kit_strdup_printf:
 * @format: sprintf(3) format string
 * @...:  the parameters to insert into the format string.
 * 
 * Similar to the standard C sprintf(3) function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed when no longer
 * needed.
 *
 * Returns: A newly allocated string or #NULL on OOM. Free with kit_free().
 */
char* 
kit_strdup_printf (const char *format, ...)
{
        char *s;
        va_list args;

        va_start (args, format);
        s = kit_strdup_vprintf (format, args);
        va_end (args);

        return s;
}

/**
 * kit_strdup_vprintf:
 * @format: printf(3) format string
 * @args: list of parameters to insert
 * 
 * Similar to the standard C vsprintf(3) function but safer, since it
 * calculates the maximum space required and allocates memory to hold
 * the result. The returned string should be freed when no longer
 * needed.
 *
 * Returns: A newly allocated string or #NULL on OOM. Free with kit_free().
 */
char* 
kit_strdup_vprintf (const char *format, va_list args)
{
        char *s;

#ifdef KIT_BUILD_TESTS
        char *p;
        vasprintf (&p, format, args);
        s = kit_strdup (p);
        free (p);
#else
        if (vasprintf (&s, format, args) == -1) {
                s = NULL;
        }
#endif
        return s;
}


/**
 * kit_str_has_prefix:
 * @s: string to check
 * @prefix: prefix to check for
 *
 * Determines if a string has a given prefix.
 *
 * Returns: #TRUE only if @s starts with @prefix
 */
kit_bool_t
kit_str_has_prefix (const char *s, const char *prefix)
{
        size_t s_len;
        size_t prefix_len;

        kit_return_val_if_fail (s != NULL, FALSE);
        kit_return_val_if_fail (prefix != NULL, FALSE);

        s_len = strlen (s);
        prefix_len = strlen (prefix);
        if (prefix_len > s_len)
                return FALSE;

        return strncmp (s, prefix, prefix_len) == 0;
}

/**
 * kit_str_has_suffix:
 * @s: string to check
 * @suffix: suffix to check for
 *
 * Determines if a string has a given suffix.
 *
 * Returns: #TRUE only if @s ends with @suffix
 */
kit_bool_t
kit_str_has_suffix (const char *s, const char *suffix)
{
        size_t s_len;
        size_t suffix_len;

        kit_return_val_if_fail (s != NULL, FALSE);
        kit_return_val_if_fail (suffix != NULL, FALSE);

        s_len = strlen (s);
        suffix_len = strlen (suffix);
        if (suffix_len > s_len)
                return FALSE;

        return strncmp (s + s_len - suffix_len, suffix, suffix_len) == 0;
}

/**
 * kit_strsplit:
 * @s: string to split
 * @delim: delimiter used for splitting
 * @num_tokens: return location for number of elements or #NULL
 *
 * Split a given string into components given a delimiter.
 *
 * Returns: A #NULL terminated array of strings. Free with kit_strfreev(). Returns #NULL on OOM.
 */
char **
kit_strsplit (const char *s, char delim, size_t *num_tokens)
{
        int n;
        int m;
        int num;
        char **result;

        kit_return_val_if_fail (s != NULL, NULL);

        result = NULL;

        num = 0;
        for (n = 0; s[n] != '\0'; n++) {
                if (s[n] == delim) {
                        num++;
                }
        }
        num++;

        result = kit_new0 (char*, num + 1);
        if (result == NULL)
                goto oom;

        m = 0;
        for (n = 0; n < num; n++) {
                int begin;

                begin = m;

                while (s[m] != delim)
                        m++;

                result[n] = kit_strndup (s + begin, m - begin);
                if (result[n] == NULL)
                        goto oom;

                m++;
        }
        result[n] = NULL;

        if (num_tokens != NULL)
                *num_tokens = num;

        return result;
oom:
        kit_strfreev (result);
        return NULL;
}

/**
 * kit_strfreev:
 * @str_array: string array
 *
 * Free a #NULL terminated string array.
 */
void
kit_strfreev (char **str_array)
{
        int n;

        if (str_array == NULL)
                return;

        for (n = 0; str_array[n] != NULL; n++)
                kit_free (str_array[n]);

        kit_free (str_array);
}

/**
 * kit_strv_length:
 * @str_array: string array
 *
 * Compute number of elements in a #NULL terminated string array.
 *
 * Returns: Number of elements not including the terminating #NULL
 */
size_t
kit_strv_length (char **str_array)
{
        int n;

        kit_return_val_if_fail (str_array != NULL, 0);

        for (n = 0; str_array[n] != NULL; n++)
                ;

        return n;
}

/**
 * kit_str_append:
 * @s: either %NULL or a string previously allocated on the heap
 * @s2: string to append
 *
 * Append a string to an existing string.
 *
 * Returns: %NULL on OOM or the new string; possibly at the same
 * location as @s.
 */
char *
kit_str_append (char *s, const char *s2)
{
        char *p;
        size_t s_len;
        size_t s2_len;

        kit_return_val_if_fail (s2 != NULL, NULL);

        if (s != NULL)
                s_len = strlen (s);
        else
                s_len = 0;
        s2_len = strlen (s2);
        p = (char *) kit_realloc ((void *) s, s_len + s2_len + 1);
        if (p == NULL)
                goto oom;
        s = p;
        memcpy ((void *) (s + s_len), s2, s2_len);
        s[s_len + s2_len] = '\0';

        return s;
oom:
        return NULL;
}


#ifdef KIT_BUILD_TESTS

static kit_bool_t
_run_test (void)
{
        char str[] = "Hello world";
        char *p;
        char *p2;
        char **tokens;
        size_t num_tokens;

        if ((p = kit_strdup (str)) != NULL) {
                kit_assert (strcmp (p, "Hello world") == 0);
                kit_free (p);
        }

        if ((p = kit_strndup (str, 5)) != NULL) {
                kit_assert (strcmp (p, "Hello") == 0);
                kit_free (p);
        }

        if ((p = kit_strndup (str, 100)) != NULL) {
                kit_assert (strcmp (p, "Hello world") == 0);
                kit_free (p);
        }

        if ((p = kit_strdup_printf ("Hello %d", 5)) != NULL) {
                kit_assert (strcmp (p, "Hello 5") == 0);
                kit_free (p);
        }

        kit_assert ( kit_str_has_suffix ("12345", "45"));
        kit_assert ( kit_str_has_suffix ("12345", "12345"));
        kit_assert (!kit_str_has_suffix ("12345", "123456"));

        kit_assert ( kit_str_has_prefix ("12345", "12"));
        kit_assert ( kit_str_has_prefix ("12345", "12345"));
        kit_assert (!kit_str_has_prefix ("12345", "123456"));

        if ((tokens = kit_strsplit ("abc:012:xyz", ':', &num_tokens)) != NULL)  {
                kit_assert (num_tokens == 3);
                kit_assert (kit_strv_length (tokens) == 3);
                kit_assert (strcmp (tokens[0], "abc") == 0);
                kit_assert (strcmp (tokens[1], "012") == 0);
                kit_assert (strcmp (tokens[2], "xyz") == 0);
                kit_strfreev (tokens);
        }

        if ((tokens = kit_strsplit ("abc012xyz", ':', &num_tokens)) != NULL)  {
                kit_assert (num_tokens == 1);
                kit_assert (kit_strv_length (tokens) == 1);
                kit_assert (strcmp (tokens[0], "abc012xyz") == 0);
                kit_strfreev (tokens);
        }

        if ((tokens = kit_strsplit ("", ':', &num_tokens)) != NULL)  {
                kit_assert (num_tokens == 1);
                kit_assert (kit_strv_length (tokens) == 1);
                kit_assert (strcmp (tokens[0], "") == 0);
                kit_strfreev (tokens);
        }

        if ((p = kit_strdup ("foobar")) != NULL) {
                if ((p2 = kit_str_append (p, "_cool")) != NULL) {
                        p = p2;

                        kit_assert (strcmp (p, "foobar_cool") == 0);
                }

                kit_free (p);
        }

        if ((p = kit_str_append (NULL, "baz")) != NULL) {
                kit_assert (strcmp (p, "baz") == 0);
                kit_free (p);
        }


        return TRUE;
}

KitTest _test_string = {
        "kit_string",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

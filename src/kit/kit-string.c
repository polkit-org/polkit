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
#include <errno.h>

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

                while (s[m] != delim && s[m] != '\0') {
                        m++;
                }

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

static kit_bool_t
_is_reserved (char c)
{
        unsigned int n;
        char reserved[] = " !*'();:@&=+$,/?%#[]\n\r\t";

        for (n = 0; n < sizeof (reserved); n++) {
                if (reserved[n] == c)
                        return TRUE;
        }

        return FALSE;
}

static char
_to_hex (unsigned int nibble)
{
        if (nibble < 10)
                return nibble + '0';
        else
                return nibble - 10 + 'A';
}

/**
 * kit_string_percent_encode:
 * @buf: return location for output
 * @buf_size: size of buffer
 * @s: string to encode
 *
 * Percent encodes a string; each occurence of an ASCII characters in
 * the set <literal>" !*'();:@&=+$,/?%#[]\n\r\t"</literal> will be
 * replaced by a three character sequence started by the percent sign
 * "%" and then the hexidecimal representation of the ASCII character
 * in question.
 *
 * Returns: This function do not write more than @buf_size bytes
 * (including the trailing zero). If the output was truncated due to
 * this limit then the return value is the number of characters (not
 * including the trailing zero) which would have been written to the
 * final string if enough space had been available. Thus, a return
 * value of size or more means that the output was truncated.
 */
size_t
kit_string_percent_encode (char *buf, size_t buf_size, const char *s)
{
        size_t len;
        unsigned int n;
        unsigned int m;

        kit_return_val_if_fail (buf != NULL, 0);
        kit_return_val_if_fail (s != NULL, 0);

        len = strlen (s);

        for (n = 0, m = 0; n < len; n++) {
                int c = s[n];

                if (_is_reserved (c)) {
                        if (m < buf_size)
                                buf[m] = '%';
                        m++;
                        if (m < buf_size)
                                buf[m] = _to_hex (c >> 4);
                        m++;
                        if (m < buf_size)
                                buf[m] = _to_hex (c & 0x0f);
                        m++;
                } else {
                        if (m < buf_size)
                                buf[m] = c;
                        m++;
                }
        }
        if (m < buf_size)
                buf[m] = '\0';

        return m;
}

/**
 * kit_string_percent_decode:
 * @s: string to modify in place
 *
 * Percent-decodes a string in place. See kit_string_percent_encode()
 * for details on the encoding format.
 *
 * Returns: %FALSE if string is not properly encoded (and errno will be set to EINVAL)
 */
kit_bool_t
kit_string_percent_decode (char *s)
{
        kit_bool_t ret;
        unsigned int n;
        unsigned int m;
        size_t len;

        kit_return_val_if_fail (s != NULL, FALSE);

        ret = FALSE;

        len = strlen (s);

        for (n = 0, m = 0; n < len; n++) {
                int c = s[n];

                if (c != '%') {
                        if (_is_reserved (c)) {
                                errno = EINVAL;
                                goto out;
                        }
                        s[m++] = s[n];
                } else {
                        int nibble1;
                        int nibble2;

                        if (n + 2 >= len) {
                                errno = EINVAL;
                                goto out;
                        }

                        nibble1 = s[n + 1];
                        nibble2 = s[n + 2];
                        n += 2;

                        if (nibble1 >= '0' && nibble1 <= '9') {
                                nibble1 -= '0';
                        } else if (nibble1 >= 'A' && nibble1 <= 'F') {
                                nibble1 -= 'A' - 10;
                        } else {
                                errno = EINVAL;
                                goto out;
                        }

                        if (nibble2 >= '0' && nibble2 <= '9') {
                                nibble2 -= '0';
                        } else if (nibble2 >= 'A' && nibble2 <= 'F') {
                                nibble2 -= 'A' - 10;
                        } else {
                                errno = EINVAL;
                                goto out;
                        }

                        s[m++] = (nibble1 << 4) | nibble2;
                }
        }
        s[m] = '\0';

        ret = TRUE;
out:
        return ret;
}


/**
 * kit_string_entry_parse:
 * @entry: line to parse
 * @func: callback function
 * @user_data: user data to pass to @func
 *
 * Parse a line of the form
 * <literal>key1=val1:key2=val2:key3=val3</literal>. 
 *
 * The given @entry is said not to be wellformed if a) it doesn't
 * follow this structure (for example
 * <literal>key1=val1:key2:key3=val3</literal> is not well-formed
 * because it's missing the '=' character) or the extracted key and
 * value strings are not properly percent encoded.
 *
 * Both the key and value values are run through the
 * kit_string_percent_decode() function prior to being passed to
 * @func. Normally this function is used to decode strings produced
 * with kit_string_entry_create().
 *
 * Returns: %TRUE if the line is wellformed and the callback didn't
 * short-circuit the iteration. Returns %FALSE on OOM (and errno will
 * be set to ENOMEM) or if @entry is not wellformed (and errno will
 * be set to EINVAL).
 */
kit_bool_t
kit_string_entry_parse (const char *entry, KitStringEntryParseFunc func, void *user_data)
{
        unsigned int n;
        kit_bool_t ret;
        char **tokens;
        size_t num_tokens;

        kit_return_val_if_fail (entry != NULL, FALSE);
        kit_return_val_if_fail (func != NULL, FALSE);

        ret = FALSE;
        tokens = NULL;

        tokens = kit_strsplit (entry, ':', &num_tokens);
        if (tokens == NULL) {
                errno = ENOMEM;
                goto out;
        }

        for (n = 0; n < num_tokens; n++) {
                char *token;
                char *p;

                token = tokens[n];

                p = strchr (token, '=');
                if (p == NULL) {
                        errno = EINVAL;
                        goto out;
                }

                token [p - token] = '\0';

                p++;

                if (!kit_string_percent_decode (token))
                        goto out;

                if (!kit_string_percent_decode (p))
                        goto out;

                if (!func (token, p, user_data)) {
                        goto out;
                }
        }

        ret = TRUE;

out:
        if (tokens != NULL)
                kit_strfreev (tokens);
        return ret;
}

/**
 * kit_string_entry_createv:
 * @buf: return location for output
 * @buf_size: size of buffer
 * @kv_pairs: %NULL terminated array of key/value pairs.
 *
 * Takes an array of key/value pairs and generates a string
 * <literal>"k1=v1:k2=v2:...:k_n=v_n"</literal> where
 * <literal>k_i</literal> and <literal>v_i</literal> are percent
 * encoded representations of the given key/value pairs. The string
 * will have a newline (ASCII character 10) at end.
 *
 * The string can later be parsed with kit_string_entry_parse() to get
 * the exact same list of key/value pairs back.
 *
 * Returns: This function do not write more than @buf_size bytes
 * (including the trailing zero). If the output was truncated due to
 * this limit then the return value is the number of characters (not
 * including the trailing zero) which would have been written to the
 * final string if enough space had been available. Thus, a return
 * value of size or more means that the output was truncated.
 *
 * If an uneven number of strings are given, this function will return
 * zero and errno will be set to EINVAL.
 */
size_t
kit_string_entry_createv (char *buf, size_t buf_size, const char *kv_pairs[])
{
        int n;
        unsigned int m;

        for (n = 0, m = 0; kv_pairs[n] != NULL; n+= 2) {
                const char *key;
                const char *value;

                if (kv_pairs[n + 1] == NULL) {
                        m = 0;
                        errno = EINVAL;
                        goto out;
                }

                key = kv_pairs[n];
                value = kv_pairs[n + 1];

                if (n > 0) {
                        if (m < buf_size)
                                buf[m] = ':';
                        m++;
                }

                m += kit_string_percent_encode (buf + m, buf_size - m > 0 ? buf_size - m : 0, key);

                if (m < buf_size)
                        buf[m] = '=';
                m++;

                m += kit_string_percent_encode (buf + m, buf_size - m > 0 ? buf_size - m : 0, value);
        }

        if (m < buf_size)
                buf[m] = '\n';
        m++;

out:
        if (m < buf_size)
                buf[m] = '\0';

        return m;
}

/**
 * kit_string_entry_create:
 * @buf: return location for output
 * @buf_size: size of buffer
 * @...: %NULL terminated array of key/value pairs.
 *
 * See kit_string_entry_create().
 *
 * Returns: See kit_string_entry_create(). Up to 64 pairs can be
 * passed; if there are more pairs, this function will return zero and
 * errno will be set to EOVERFLOW.
 */
size_t
kit_string_entry_create (char *buf, size_t buf_size, ...)
{
        int n;
        va_list args;
        const char *val;
        const char *kv_pairs[64 * 2 + 1];
        size_t ret;

        /* TODO: get rid of the 64 limit... */

        ret = 0;

        n = 0;
        va_start (args, buf_size);
        while ((val = va_arg (args, const char *)) != NULL) {
                if (n == 64 * 2) {
                        errno = EOVERFLOW;
                        goto out;
                }
                kv_pairs[n++] = val;
        }
        va_end (args);
        kv_pairs[n] = NULL;

        ret = kit_string_entry_createv (buf, buf_size, kv_pairs);
out:
        return ret;
}

#ifdef KIT_BUILD_TESTS

static kit_bool_t
_ep1 (const char *key, const char *value, void *user_data)
{
        int *n = (int *) user_data;

        if (strcmp (key, "a") == 0 && strcmp (value, "aval") == 0)
                *n += 1;
        if (strcmp (key, "a") == 0 && strcmp (value, "aval2") == 0)
                *n += 1;
        if (strcmp (key, "b") == 0 && strcmp (value, "bval") == 0)
                *n += 1;
        if (strcmp (key, "c") == 0 && strcmp (value, "cval") == 0)
                *n += 1;
        if (strcmp (key, "some_other_key") == 0 && strcmp (value, "some_value") == 0)
                *n += 1;
        if (strcmp (key, "escaped;here:right=") == 0 && strcmp (value, "yes! it's ==:crazy!") == 0)
                *n += 1;

        return TRUE;
}

static kit_bool_t
_ep2 (const char *key, const char *value, void *user_data)
{
        int *n = (int *) user_data;

        if (strcmp (key, "b") == 0)
                return FALSE;

        *n += 1;

        return TRUE;
}

static kit_bool_t
_run_test (void)
{
        int num;
        char str[] = "Hello world";
        char *p;
        char *p2;
        char **tokens;
        size_t num_tokens;
        unsigned int n;
        char *bad_strings[] = {"bad:",
                               "bad=",
                               "bad%",
                               "bad%1",
                               "bad%xy",
                               "bad%1x",
                               "bad%Ax",
                               "bad%2a"};
        char buf[256];

        kit_assert (kit_string_percent_encode (buf, sizeof (buf), "Hello World; Nice day!") < sizeof (buf));
        kit_assert (strcmp (buf, "Hello%20World%3B%20Nice%20day%21") == 0);
        kit_assert (kit_string_percent_decode (buf));
        kit_assert (strcmp (buf, "Hello World; Nice day!") == 0);

        for (n = 0; n < sizeof (bad_strings) / sizeof (char *); n++) {
                if ((p = kit_strdup (bad_strings[n])) != NULL) {
                        kit_assert (!kit_string_percent_decode (p) && errno == EINVAL);
                        kit_free (p);
                }
        }

        kit_assert (kit_string_entry_create (buf, sizeof (buf), 
                                             "key1", "val1",
                                             "key2", "val2",
                                             "key3", "val3",
                                             NULL) < sizeof (buf) &&
                    strcmp (buf, "key1=val1:key2=val2:key3=val3") == 0);

        kit_assert (kit_string_entry_create (buf, sizeof (buf), 
                                             "key1;", "val1=val1x",
                                             "key2%", "val2!",
                                             NULL) < sizeof (buf) &&
                    strcmp (buf, "key1%3B=val1%3Dval1x:key2%25=val2%21") == 0);

        kit_assert (kit_string_entry_create (buf, sizeof (buf), 
                                             "key1", "val1",
                                             "key2", NULL) == 0 && errno == EINVAL);

        kit_assert (kit_string_entry_create (buf, 3, 
                                             "key1", "val1",
                                             "key2", "val2", NULL) > 3);

        kit_assert (kit_string_entry_create (buf, sizeof (buf), 
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "a","a","a","a","a","a","a","a","a","a","a","a","a","a","a","a",
                                             "b", "c", NULL) == 0 && errno == EOVERFLOW);

        kit_assert (!kit_string_entry_parse ("key=val:invalidkeyval:key2=val2", _ep1, &num) && 
                    (errno == EINVAL || errno == ENOMEM));
        kit_assert (!kit_string_entry_parse ("key;=val:key2=val2", _ep1, &num) && 
                    (errno == EINVAL || errno == ENOMEM));
        kit_assert (!kit_string_entry_parse ("key=val:key2=val2;", _ep1, &num) && 
                    (errno == EINVAL || errno == ENOMEM));

        kit_assert (kit_string_entry_create (buf, sizeof (buf), 
                                             "a", "aval",
                                             "a", "aval2",
                                             "b", "bval",
                                             "c", "cval",
                                             "some_other_key", "some_value",
                                             "escaped;here:right=", "yes! it's ==:crazy!",
                                             NULL) < sizeof (buf));
        num = 0;
        if (kit_string_entry_parse (buf, _ep1, &num)) {
                kit_assert (num == 6);
        } else {
                kit_assert (errno == ENOMEM);
        }

        num = 0; 
        errno = 0;
        kit_assert (!kit_string_entry_parse ("a=0:b=1:c=2", _ep2, &num));
        if (num > 0)
                kit_assert (errno == 0);
        else
                kit_assert (errno == ENOMEM);


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

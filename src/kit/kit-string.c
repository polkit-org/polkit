/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-string.c : String utilities
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

#ifdef HAVE_SOLARIS
int vasprintf(char **strp, const char *fmt, va_list ap)
{
        int size;
        va_list ap2;
        char s;

        *strp = NULL;
        va_copy(ap2, ap);
        size = vsnprintf(&s, 1, fmt, ap2);
        va_end(ap2);
        *strp = malloc(size + 1);
        if (!*strp)
                return -1;
        vsnprintf(*strp, size + 1, fmt, ap);

        return size;
}
#endif

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
 * value of @buf_size or more means that the output was truncated.
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
 * encoded representations of the given key/value pairs.
 *
 * The string can later be parsed with kit_string_entry_parse() to get
 * the exact same list of key/value pairs back.
 *
 * Returns: This function do not write more than @buf_size bytes
 * (including the trailing zero). If the output was truncated due to
 * this limit then the return value is the number of characters (not
 * including the trailing zero) which would have been written to the
 * final string if enough space had been available. Thus, a return
 * value of @buf_size or more means that the output was truncated.
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

/**
 * KitString:
 *
 * String buffer that grows automatically as text is added.
 */
struct _KitString {
        char *buf;
        size_t cur_len;
        size_t buf_len;
};

/**
 * kit_string_free:
 * @s: the #KitString object
 * @free_segment: whether to free the string data itself
 * @out_segment_size: return location for size of string or %NULL
 *
 * Free resources used by a #KitString object
 *
 * Returns: If @free_segment is %TRUE, returns the segment (will
 * always be zero terminated), must be freed with kit_free(),
 * otherwise %NULL
 */
char *
kit_string_free (KitString *s, kit_bool_t free_segment, size_t *out_segment_size)
{
        char *ret;

        kit_return_val_if_fail (s != NULL, NULL);

        if (out_segment_size != NULL) {
                *out_segment_size = s->cur_len;
        }

        if (free_segment) {
                kit_free (s->buf);
                ret = NULL;
        } else {
                ret = s->buf;
        }
        kit_free (s);

        return ret;
}

#define KIT_STRING_BLOCK_SIZE 256

/**
 * kit_string_new:
 * @init: String to initialize with or %NULL
 * @len: Initial size of buffer; pass zero to use the default size
 *
 * Initialize a new #KitString object.
 *
 * Returns: The new object or %NULL on OOM
 */
KitString *
kit_string_new (const char *init, size_t len)
{
        KitString *s;

        s = kit_new0 (KitString, 1);
        if (s == NULL)
                goto oom;

        if (len == 0)
                len = KIT_STRING_BLOCK_SIZE;
        s->buf_len = len;

        if (init == NULL) {
                s->buf = kit_new0 (char, s->buf_len);
                if (s->buf == NULL)
                        goto oom;
                s->cur_len = 0;
        } else {
                size_t init_len;

                init_len = strlen (init);
                if (init_len + 1 > s->buf_len)
                        s->buf_len = init_len + 1;
                s->buf = kit_new0 (char, s->buf_len);
                if (s->buf == NULL)
                        goto oom;
                strncpy (s->buf, init, init_len);
                s->cur_len = init_len;
        }

        return s;
oom:
        if (s != NULL)
                kit_string_free (s, TRUE, NULL);
        return NULL;
}

/**
 * kit_string_ensure_size:
 * @s: String object
 * @new_size: The size to check for.
 *
 * Ensure that the given #KitString object can hold at least @new_size
 * characters.
 *
 * Returns: %TRUE if the given #KitString object can hold at least
 * @new_size characters. %FALSE if OOM.
 */
kit_bool_t
kit_string_ensure_size (KitString *s, size_t new_size)
{
        kit_return_val_if_fail (s != NULL, FALSE);

        if (new_size > s->buf_len - 1) {
                char *p;
                size_t grow_to;

                grow_to = ((new_size / KIT_STRING_BLOCK_SIZE) + 1) * KIT_STRING_BLOCK_SIZE;

                p = kit_realloc (s->buf, grow_to);
                if (p == NULL)
                        goto oom;
                /* zero the new block we got */
                memset (s->buf + s->buf_len, 0, grow_to - s->buf_len);
                s->buf = p;
                s->buf_len += KIT_STRING_BLOCK_SIZE;
        }

        return TRUE;
oom:
        return FALSE;
}

/**
 * kit_string_append_c:
 * @s: the #KitString object
 * @c: character to append
 *
 * Append a character to a #KitString object.
 *
 * Returns: %TRUE unless OOM
 */
kit_bool_t
kit_string_append_c (KitString *s, char c)
{
        kit_return_val_if_fail (s != NULL, FALSE);

        if (!kit_string_ensure_size (s, s->cur_len + 1))
                goto oom;

        s->buf[s->cur_len] = c;
        s->cur_len += 1;
        return TRUE;
oom:
        return FALSE;
}

/**
 * kit_string_append:
 * @s: the #KitString object
 * @str: string to append
 *
 * Append a string to a #KitString object.
 *
 * Returns: %TRUE unless OOM
 */
kit_bool_t
kit_string_append (KitString *s, const char *str)
{
        size_t str_len;

        kit_return_val_if_fail (s != NULL, FALSE);

        str_len = strlen (str);

        if (!kit_string_ensure_size (s, s->cur_len + str_len))
                goto oom;

        strncpy (s->buf + s->cur_len, str, str_len);
        s->cur_len += str_len;
        return TRUE;
oom:
        return FALSE;
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
        KitString *s;

        if ((s = kit_string_new (NULL, 3)) != NULL) {
                for (n = 0; n < 8; n++) {
                        if (!kit_string_append_c (s, 'd'))
                                break;
                }
                p = kit_string_free (s, FALSE, NULL);
                if (n == 8) {
                        kit_assert (strcmp ("dddddddd", p) == 0);
                }
                kit_free (p);
        }

        /* KitString always makes place for the terminating zero, hence allocate one more byte */
        if ((s = kit_string_new (NULL, 101)) != NULL) {
                size_t segment_size;
                for (n = 0; n < 100; n++) {
                        kit_assert (kit_string_append_c (s, n));
                }
                p = kit_string_free (s, FALSE, &segment_size);
                kit_assert (segment_size == 100);
                for (n = 0; n < 100; n++) {
                        kit_assert (p[n] == (char) n);
                }
                kit_assert (p[100] == 0);
                kit_free (p);
        }

        if ((s = kit_string_new (NULL, 0)) != NULL) {
                for (n = 0; n < 100; n++) {
                        if (!kit_string_append (s, "foobar"))
                                break;
                }
                p = kit_string_free (s, FALSE, NULL);
                if (n == 100) {
                        kit_assert (strlen (p) == 600);
                        for (n = 0; n < 100; n++) {
                                kit_assert (strncmp ("foobar", p + n * 6, 6) == 0);
                        }
                }
                kit_free (p);
        }

        if ((s = kit_string_new ("fooobar", 3)) != NULL) {
                p = kit_string_free (s, FALSE, NULL);
                kit_assert (strcmp ("fooobar", p) == 0);
                kit_free (p);
        }

        if ((s = kit_string_new ("fooobar2", 100)) != NULL) {
                p = kit_string_free (s, FALSE, NULL);
                kit_assert (strcmp ("fooobar2", p) == 0);
                kit_free (p);
        }


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

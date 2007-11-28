/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-string.h : String utilities
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

#if !defined (KIT_COMPILATION) && !defined(_KIT_INSIDE_KIT_H)
#error "Only <kit/kit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef KIT_STRING_H
#define KIT_STRING_H

#include <kit/kit.h>

KIT_BEGIN_DECLS

char *kit_strdup         (const char *s);
char *kit_strndup        (const char *s, size_t n);
char *kit_strdup_printf  (const char *format, ...) __attribute__((__format__ (__printf__, 1, 2)));
char *kit_strdup_vprintf (const char *format, va_list args);
char *kit_str_append     (char *s, const char *s2);

kit_bool_t kit_str_has_prefix (const char *s, const char *prefix);
kit_bool_t kit_str_has_suffix (const char *s, const char *suffix);

char **kit_strsplit (const char *s, char delim, size_t *num_tokens);

void kit_strfreev (char **str_array);
size_t kit_strv_length (char **str_array);

/**
 * KitStringEntryParseFunc:
 * @key: key of one of the entries
 * @value: value of one of the entries
 * @user_data: user data passed to kit_string_entry_parse()
 *
 * Type of callback function to use in kit_string_entry_parse()
 *
 * Returns: If %FALSE is returned the parsing will be aborted and
 * kit_string_entry_parse() will return FALSE.
 */
typedef kit_bool_t (*KitStringEntryParseFunc) (const char *key, const char *value, void *user_data);

kit_bool_t kit_string_entry_parse (const char *entry, KitStringEntryParseFunc func, void *user_data);

kit_bool_t  kit_string_percent_decode (char *s);
size_t      kit_string_percent_encode (char *buf, size_t buf_size, const char *s);

size_t      kit_string_entry_create (char *buf, size_t buf_size, ...);
size_t      kit_string_entry_createv (char *buf, size_t buf_size, const char *kv_pairs[]);


KIT_END_DECLS

#endif /* KIT_STRING_H */



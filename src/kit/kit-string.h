/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-string.h : String utilities
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

kit_bool_t kit_str_has_prefix (const char *s, const char *prefix);
kit_bool_t kit_str_has_suffix (const char *s, const char *suffix);

KIT_END_DECLS

#endif /* KIT_STRING_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-types.h : fundamental types such as polkit_bool_t
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_TYPES_H
#define POLKIT_TYPES_H

#ifdef __cplusplus
#  define POLKIT_BEGIN_DECLS extern "C" {
#  define POLKIT_END_DECLS }
#else
/**
 * POLKIT_BEGIN_DECLS:
 *
 * C++ include header guard.
 */
#  define POLKIT_BEGIN_DECLS
/**
 * POLKIT_END_DECLS:
 *
 * C++ include header guard.
 */
#  define POLKIT_END_DECLS
#endif

#if    __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define POLKIT_GNUC_DEPRECATED                            \
  __attribute__((__deprecated__))
#else
/**
 * POLKIT_GNUC_DEPRECATED:
 *
 * Used in front of deprecated functions.
 */
#define POLKIT_GNUC_DEPRECATED
#endif /* __GNUC__ */

POLKIT_BEGIN_DECLS

/**
 * SECTION:polkit-types
 * @title: Basic types
 * @short_description: Type definitions for common primitive types.
 *
 * Type definitions for common primitive types.
 **/

/**
 * polkit_bool_t:
 *
 * A boolean, valid values are #TRUE and #FALSE.
 */
typedef int polkit_bool_t;

/**
 * polkit_uint32_t:
 *
 * Type for unsigned 32 bit integer.
 */
typedef unsigned int polkit_uint32_t;

/**
 * polkit_uint64_t:
 *
 * Type for unsigned 64 bit integer.
 */
typedef unsigned long long polkit_uint64_t;

#ifndef TRUE
#  define TRUE 1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

POLKIT_END_DECLS

#endif /* POLKIT_TYPES_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit.h : OOM-safe utility library
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

#ifndef KIT_H
#define KIT_H

/**
 * SECTION:kit
 * @title: Macros
 * @short_description: Macros
 *
 * Various low-level macros.
 **/

#ifdef __cplusplus
#  define KIT_BEGIN_DECLS extern "C" {
#  define KIT_END_DECLS }
#else
/**
 * KIT_BEGIN_DECLS:
 *
 * C++ include header guard.
 */
#  define KIT_BEGIN_DECLS
/**
 * KIT_END_DECLS:
 *
 * C++ include header guard.
 */
#  define KIT_END_DECLS
#endif

/**
 * kit_bool_t:
 *
 * A boolean, valid values are #TRUE and #FALSE.
 */
typedef int kit_bool_t;

#ifndef TRUE
#  define TRUE 1
#endif
#ifndef FALSE
#  define FALSE 0
#endif

/**
 * kit_assert:
 * @expr: expression
 *
 * Debugging macro to terminate the application if the assertion
 * fails. If the assertion fails (i.e. the expression is not true), an
 * error message is logged and the application is terminated.
 */
#define kit_assert(expr)                                                                        \
do {                                                                                            \
        if (expr) {                                                                             \
                ;                                                                               \
        } else {                                                                                \
                kit_warning ("%s:%d:%s(): %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr); \
                exit (1);                                                                       \
        }                                                                                       \
} while (0)

/**
 * kit_return_if_fail:
 * @expr: expression
 *
 * Returns from the current function if the expression is not true. If
 * the expression evaluates to #FALSE, an error message is logged and
 * the function returns. This can only be used in functions which do
 * not return a value.
 */
#define kit_return_if_fail(expr)                                                                \
do {                                                                                            \
        if (expr) {                                                                             \
                ;                                                                               \
        } else {                                                                                \
                kit_warning ("%s:%d:%s(): %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr); \
                return;                                                                         \
        }                                                                                       \
} while (0)

/**
 * kit_return_val_if_fail:
 * @expr: expression
 * @val: the value to return if the expression evaluates does not
 * evaluate to #TRUE
 *
 * Returns from the current function, returning the value @val, if the
 * expression is not true. If the expression evaluates to #FALSE, an
 * error message is logged and val is returned.
 */
#define kit_return_val_if_fail(expr,val)                                                        \
do {                                                                                            \
        if (expr) {                                                                             \
                ;                                                                               \
        } else {                                                                                \
                kit_warning ("%s:%d:%s(): %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr); \
                return val;                                                                     \
        }                                                                                       \
} while (0)



#define _KIT_INSIDE_KIT_H 1

#include <kit/kit-memory.h>
#include <kit/kit-string.h>
#include <kit/kit-list.h>
#include <kit/kit-hash.h>
#include <kit/kit-file.h>
#include <kit/kit-message.h>

#undef _KIT_INSIDE_KIT_H

#endif /* KIT_H */



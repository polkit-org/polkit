/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit.h : OOM-safe utility library
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

void kit_print_backtrace (void);

#ifdef HAVE_SOLARIS
#define __PRETTY_FUNCTION__ __func__
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
                kit_print_backtrace ();                                                         \
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
 *
 * Returns: nothing
 */
#define kit_return_if_fail(expr)                                                                \
do {                                                                                            \
        if (expr) {                                                                             \
                ;                                                                               \
        } else {                                                                                \
                kit_warning ("%s:%d:%s(): %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr); \
                kit_print_backtrace ();                                                         \
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
 *
 * Returns: nothing
 */
#define kit_return_val_if_fail(expr,val)                                                        \
do {                                                                                            \
        if (expr) {                                                                             \
                ;                                                                               \
        } else {                                                                                \
                kit_warning ("%s:%d:%s(): %s", __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr); \
                kit_print_backtrace ();                                                         \
                return val;                                                                     \
        }                                                                                       \
} while (0)



#define _KIT_INSIDE_KIT_H 1

#ifdef HAVE_SOLARIS
#include <sys/types.h>
#endif
#include <kit/kit-memory.h>
#include <kit/kit-string.h>
#include <kit/kit-list.h>
#include <kit/kit-hash.h>
#include <kit/kit-file.h>
#include <kit/kit-spawn.h>
#include <kit/kit-message.h>
#include <kit/kit-test.h>
#include <kit/kit-entity.h>

#undef _KIT_INSIDE_KIT_H

#endif /* KIT_H */



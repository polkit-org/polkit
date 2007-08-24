/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-types.h : fundamental types such as polkit_bool_t
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_TYPES_H
#define POLKIT_TYPES_H

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

#endif /* POLKIT_TYPES_H */



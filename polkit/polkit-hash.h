/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-hash.h : Hash tables
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

#ifndef POLKIT_HASH_H
#define POLKIT_HASH_H

#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

struct _PolKitHash;
typedef struct _PolKitHash PolKitHash;

/**
 * PolKitHashFunc:
 * @key: a key
 *
 * The function is passed a key and should return a hash value. The
 * functions p_direct_hash(), p_int_hash() and p_str_hash() provide
 * hash functions which can be used when the key is a pointer, an
 * integer, and char* respectively.
 *
 * Returns: the hash value corresponding to the key
 *
 * Since: 0.7
 */
typedef polkit_uint32_t (*PolKitHashFunc) (const void *key);

/**
 * PolKitEqualFunc:
 * @key1: first key
 * @key2: second key
 *
 * Determines if two keys are equal.
 *
 * Returns: #TRUE iff the keys are equal
 *
 * Since: 0.7
 */
typedef polkit_bool_t (*PolKitEqualFunc) (const void *key1, const void *key2);

/**
 * PolKitFreeFunc:
 * @p: pointer
 *
 * Specifies the type of function which is called when a data element
 * is destroyed. It is passed the pointer to the data element and
 * should free any memory and resources allocated for it.
 *
 * Since: 0.7
 */
typedef void (*PolKitFreeFunc) (void *p);


PolKitHash *polkit_hash_new (PolKitHashFunc  hash_func,
                             PolKitEqualFunc key_equal_func,
                             PolKitFreeFunc  key_destroy_func,
                             PolKitFreeFunc  value_destroy_func);

PolKitHash    *polkit_hash_ref   (PolKitHash *hash);
void           polkit_hash_unref (PolKitHash *hash);

polkit_bool_t  polkit_hash_insert (PolKitHash *hash, void *key, void *value);

void          *polkit_hash_lookup (PolKitHash *hash, void *key, polkit_bool_t *found);

polkit_uint32_t p_direct_hash (const void *key);
polkit_uint32_t p_str_hash (const void *key);


polkit_bool_t p_direct_equal (const void *v1, const void *v2);
polkit_bool_t p_str_equal (const void *v1, const void *v2);

POLKIT_END_DECLS

#endif /* POLKIT_TEST_H */



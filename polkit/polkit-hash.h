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
 * functions polkit_hash_direct_hash_func() and
 * polkit_hash_str_hash_func() provide hash functions which can be
 * used when the key is a pointer and an char* respectively.
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
 * Determines if two keys are equal. The functions
 * polkit_hash_direct_equal_func() and polkit_hash_str_equal_func()
 * provide equality functions which can be used when the key is a
 * pointer and an char* respectively.
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
 * should free any memory and resources allocated for it. The function
 * p_free() or any of the object unref functions can be passed here.
 *
 * Since: 0.7
 */
typedef void (*PolKitFreeFunc) (void *p);

/**
 * PolKitCopyFunc:
 * @p: pointer
 *
 * Specifies the type of function which is called when a data element
 * is to be cloned or reffed. It is passed the pointer to the data
 * element and should return a new pointer to a reffed or cloned
 * object. The function polkit_hash_str_copy() or any of the object
 * ref functions can be passed here.
 *
 * Returns: A copy or ref of the object in question
 *
 * Since: 0.7
 */
typedef void *(*PolKitCopyFunc) (const void *p);

/**
 * PolKitHashForeachFunc:
 * @hash: the hash table
 * @key: key
 * @value: value
 * @user_data: user data passed to polkit_hash_foreach()
 *
 * Type signature for callback function used in polkit_hash_foreach().
 *
 * Returns: Return #TRUE to short-circuit, e.g. stop the iteration.
 *
 * Since: 0.7
 */
typedef polkit_bool_t (*PolKitHashForeachFunc) (PolKitHash *hash,
                                                void *key,
                                                void *value,
                                                void *user_data);


PolKitHash *polkit_hash_new (PolKitHashFunc  hash_func,
                             PolKitEqualFunc key_equal_func,
                             PolKitCopyFunc  key_copy_func,
                             PolKitCopyFunc  value_copy_func,
                             PolKitFreeFunc  key_destroy_func,
                             PolKitFreeFunc  value_destroy_func);

PolKitHash    *polkit_hash_ref   (PolKitHash *hash);
void           polkit_hash_unref (PolKitHash *hash);

polkit_bool_t  polkit_hash_insert (PolKitHash *hash, void *key, void *value);

void          *polkit_hash_lookup (PolKitHash *hash, void *key, polkit_bool_t *found);

polkit_bool_t  polkit_hash_foreach (PolKitHash *hash, PolKitHashForeachFunc cb, void *user_data);


polkit_uint32_t polkit_hash_direct_hash_func  (const void *key);
polkit_bool_t   polkit_hash_direct_equal_func (const void *v1, const void *v2);

polkit_uint32_t polkit_hash_str_hash_func     (const void *key);
polkit_bool_t   polkit_hash_str_equal_func    (const void *v1, const void *v2);
void           *polkit_hash_str_copy          (const void *p);

POLKIT_END_DECLS

#endif /* POLKIT_HASH_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-hash.h : Hash tables
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

#ifndef KIT_HASH_H
#define KIT_HASH_H

#include <stdint.h>
#include <kit/kit.h>

KIT_BEGIN_DECLS

struct _KitHash;
typedef struct _KitHash KitHash;

/**
 * KitHashFunc:
 * @key: a key
 *
 * The function is passed a key and should return a hash value. The
 * functions kit_hash_direct_hash_func() and
 * kit_hash_str_hash_func() provide hash functions which can be
 * used when the key is a pointer and an char* respectively.
 *
 * Returns: the hash value corresponding to the key
 */
typedef uint32_t (*KitHashFunc) (const void *key);

/**
 * KitEqualFunc:
 * @key1: first key
 * @key2: second key
 *
 * Determines if two keys are equal. The functions
 * kit_hash_direct_equal_func() and kit_hash_str_equal_func()
 * provide equality functions which can be used when the key is a
 * pointer and an char* respectively.
 *
 * Returns: #TRUE iff the keys are equal
 */
typedef kit_bool_t (*KitEqualFunc) (const void *key1, const void *key2);

/**
 * KitFreeFunc:
 * @p: pointer
 *
 * Specifies the type of function which is called when a data element
 * is destroyed. It is passed the pointer to the data element and
 * should free any memory and resources allocated for it. The function
 * p_free() or any of the object unref functions can be passed here.
 */
typedef void (*KitFreeFunc) (void *p);

/**
 * KitCopyFunc:
 * @p: pointer
 *
 * Specifies the type of function which is called when a data element
 * is to be cloned or reffed. It is passed the pointer to the data
 * element and should return a new pointer to a reffed or cloned
 * object. The function kit_hash_str_copy() or any of the object
 * ref functions can be passed here.
 *
 * Returns: A copy or ref of the object in question
 */
typedef void *(*KitCopyFunc) (const void *p);

/**
 * KitHashForeachFunc:
 * @hash: the hash table
 * @key: key
 * @value: value
 * @user_data: user data passed to kit_hash_foreach()
 *
 * Type signature for callback function used in kit_hash_foreach().
 *
 * Returns: Return #TRUE to short-circuit, e.g. stop the iteration.
 */
typedef kit_bool_t (*KitHashForeachFunc) (KitHash *hash,
                                          void *key,
                                          void *value,
                                          void *user_data);


KitHash *kit_hash_new (KitHashFunc  hash_func,
                       KitEqualFunc key_equal_func,
                       KitCopyFunc  key_copy_func,
                       KitCopyFunc  value_copy_func,
                       KitFreeFunc  key_destroy_func,
                       KitFreeFunc  value_destroy_func);

KitHash    *kit_hash_ref   (KitHash *hash);
void       kit_hash_unref (KitHash *hash);

kit_bool_t  kit_hash_insert (KitHash *hash, void *key, void *value);

void       *kit_hash_lookup (KitHash *hash, void *key, kit_bool_t *found);

kit_bool_t  kit_hash_foreach (KitHash *hash, KitHashForeachFunc cb, void *user_data);


uint32_t     kit_hash_direct_hash_func  (const void *key);
kit_bool_t   kit_hash_direct_equal_func (const void *v1, const void *v2);

uint32_t     kit_hash_str_hash_func     (const void *key);
kit_bool_t   kit_hash_str_equal_func    (const void *v1, const void *v2);
void        *kit_hash_str_copy          (const void *p);

KIT_END_DECLS

#endif /* KIT_HASH_H */



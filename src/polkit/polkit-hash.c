/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-hash.c : Hash tables
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <polkit/polkit-hash.h>
#include <polkit/polkit-memory.h>
#include <polkit/polkit-test.h>

/**
 * SECTION:polkit-hash
 * @title: Hash Tables
 * @short_description: Hash Tables
 *
 * This class provides support for hash tables.
 *
 * Since: 0.7
 **/

struct _PolKitHashNode;

typedef struct _PolKitHashNode {
        void *key;
        void *value;
        struct _PolKitHashNode *next;
} PolKitHashNode;


/**
 * PolKitHash:
 *
 * The #PolKitHash structure not be accessed directly.
 *
 * Since: 0.7
 */
struct _PolKitHash
{
        int refcount;

        int num_top_nodes;
        PolKitHashNode **top_nodes;

        PolKitHashFunc  hash_func;
        PolKitEqualFunc key_equal_func;
        PolKitCopyFunc  key_copy_func;
        PolKitCopyFunc  value_copy_func;
        PolKitFreeFunc  key_destroy_func;
        PolKitFreeFunc  value_destroy_func;
};

/**
 * polkit_hash_new:
 * @hash_func: The hash function to use
 * @key_equal_func: The function used to determine key equality
 * @key_copy_func: Function for copying keys or #NULL
 * @value_copy_func: Function for copying values or #NULL
 * @key_destroy_func: Function for freeing keys or #NULL
 * @value_destroy_func: Function for freeing values or #NULL
 *
 * Creates a new Hash Table.
 *
 * Returns: The new hash table. Returns #NULL on OOM.
 *
 * Since: 0.7
 */
PolKitHash *
polkit_hash_new (PolKitHashFunc  hash_func,
                 PolKitEqualFunc key_equal_func,
                 PolKitCopyFunc  key_copy_func,
                 PolKitCopyFunc  value_copy_func,
                 PolKitFreeFunc  key_destroy_func,
                 PolKitFreeFunc  value_destroy_func)
{
        PolKitHash *h;

        g_return_val_if_fail (hash_func != NULL, NULL);
        g_return_val_if_fail (key_equal_func != NULL, NULL);

        h = p_new0 (PolKitHash, 1);
        if (h == NULL)
                goto error;

        h->refcount = 1;
        h->hash_func = hash_func;
        h->key_copy_func = key_copy_func;
        h->value_copy_func = value_copy_func;
        h->key_equal_func = key_equal_func;
        h->key_destroy_func = key_destroy_func;
        h->value_destroy_func = value_destroy_func;

        h->num_top_nodes = 11; /* TODO: configurable? */
        h->top_nodes = p_new0 (PolKitHashNode*, h->num_top_nodes);
        if (h->top_nodes == NULL)
                goto error;

        return h;
error:
        if (h != NULL)
                polkit_hash_unref (h);
        return NULL;
}

/**
 * polkit_hash_ref:
 * @hash: the hash table
 *
 * Increase reference count.
 *
 * Returns: the hash table
 *
 * Since: 0.7
 */
PolKitHash *
polkit_hash_ref (PolKitHash *hash)
{
        g_return_val_if_fail (hash != NULL, hash);
        hash->refcount++;
        return hash;
}

/**
 * polkit_hash_unref:
 * @hash: the hash table
 *
 * Decrease reference count. If reference count drop to zero the hash
 * table is freed.
 *
 * Since: 0.7
 */
void
polkit_hash_unref (PolKitHash *hash)
{
        g_return_if_fail (hash != NULL);

        hash->refcount--;
        if (hash->refcount > 0) 
                return;

        if (hash->top_nodes != NULL) {
                int n;

                for (n = 0; n < hash->num_top_nodes; n++) {
                        PolKitHashNode *node;
                        PolKitHashNode *next;
                        
                        for (node = hash->top_nodes[n]; node != NULL; node = next) {
                                if (hash->key_destroy_func != NULL)
                                        hash->key_destroy_func (node->key);
                                if (hash->value_destroy_func != NULL)
                                        hash->value_destroy_func (node->value);
                                next = node->next;
                                p_free (node);
                        }
                }
        }

        p_free (hash->top_nodes);
        p_free (hash);
}

/**
 * polkit_hash_insert:
 * @hash: the hash table
 * @key: key to insert
 * @value: value to insert
 *
 * Inserts a new key and value into a hash table. If the key already
 * exists in the hash table it's current value is replaced with the
 * new value.
 *
 * Returns: #TRUE unless OOM
 *
 * Since: 0.7
 */
polkit_bool_t 
polkit_hash_insert (PolKitHash *hash,
                    void *key,
                    void *value)
{
        int bucket;
        PolKitHashNode **nodep;
        PolKitHashNode *node;
        void *key_copy;
        void *value_copy;

        g_return_val_if_fail (hash != NULL, FALSE);
        g_return_val_if_fail (key != NULL, FALSE);

        key_copy = NULL;
        value_copy = NULL;
        if (hash->key_copy_func != NULL) {
                key_copy = hash->key_copy_func (key);
                if (key_copy == NULL) {
                        goto oom;
                }
        } else {
                key_copy = key;
        }
        if (hash->value_copy_func != NULL) {
                value_copy = hash->value_copy_func (value);
                if (value_copy == NULL) {
                        goto oom;
                }
        } else {
                value_copy = value;
        }

        bucket = hash->hash_func (key) % hash->num_top_nodes;

        nodep = & (hash->top_nodes [bucket]);
        node = hash->top_nodes [bucket];
        while (node != NULL) {
                nodep = &(node->next);

                if (hash->key_equal_func (key, node->key)) {
                        /* replace the value */

                        if (hash->key_destroy_func != NULL)
                                hash->key_destroy_func (node->key);
                        if (hash->value_destroy_func != NULL)
                                hash->value_destroy_func (node->value);

                        node->key = key_copy;
                        node->value = value_copy;

                        goto out;
                } else {
                        node = node->next;
                }
        }

        node = p_new0 (PolKitHashNode, 1);
        if (node == NULL)
                goto oom;

        node->key = key_copy;
        node->value = value_copy;
        *nodep = node;

out:
        return TRUE;

oom:
        if (key_copy != NULL && hash->key_copy_func != NULL && hash->key_destroy_func != NULL)
                hash->key_destroy_func (key_copy);

        if (value_copy != NULL && hash->value_copy_func != NULL && hash->value_destroy_func != NULL)
                hash->value_destroy_func (value_copy);

        return FALSE;
}

/**
 * polkit_hash_lookup:
 * @hash: the hash table
 * @key: key to look up
 * @found: if not #NULL, will return #TRUE only if the key was found in the hash table
 *
 * Look up a value in the hash table.
 *
 * Returns: the value; caller shall not free/unref this value
 *
 * Since: 0.7
 */
void *
polkit_hash_lookup (PolKitHash *hash, void *key, polkit_bool_t *found)
{
        int bucket;
        void *value;
        PolKitHashNode *node;

        value = NULL;
        if (found != NULL)
                *found = FALSE;

        g_return_val_if_fail (hash != NULL, NULL);
        g_return_val_if_fail (key != NULL, NULL);

        bucket = hash->hash_func (key) % hash->num_top_nodes;

        node = hash->top_nodes [bucket];
        while (node != NULL) {
                if (hash->key_equal_func (key, node->key)) {
                        /* got it */

                        value = node->value;
                        if (found != NULL)
                                *found = TRUE;
                        goto out;
                } else {
                        node = node->next;
                }
        }

out:
        return value;
}


/**
 * polkit_hash_foreach:
 * @hash: the hash table
 * @cb: callback function
 * @user_data: user data
 *
 * Iterate over all elements in a hash table
 *
 * Returns: #TRUE only if the callback short-circuited the iteration
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_hash_foreach (PolKitHash *hash, PolKitHashForeachFunc cb, void *user_data)
{
        int n;

        g_return_val_if_fail (hash != NULL, FALSE);
        g_return_val_if_fail (cb != NULL, FALSE);

        for (n = 0; n < hash->num_top_nodes; n++) {
                PolKitHashNode *node;

                for (node = hash->top_nodes[n]; node != NULL; node = node->next) {
                        if (cb (hash, node->key, node->value, user_data))
                                return TRUE;
                }
        }

        return FALSE;
}


/**
 * polkit_hash_direct_hash_func:
 * @key: the key
 *
 * Converts a pointer to a hash value.
 *
 * Returns: a hash value corresponding to the key
 *
 * Since: 0.7
 */
polkit_uint32_t 
polkit_hash_direct_hash_func (const void *key)
{
        /* TODO: reimplement */
        return g_direct_hash (key);
}

/**
 * polkit_hash_direct_equal_func:
 * @v1: first value
 * @v2: second value
 *
 * Compares two pointers and return #TRUE if they are equal (same address).
 *
 * Returns: #TRUE only if the values are equal
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_hash_direct_equal_func (const void *v1, const void *v2)
{
        /* TODO: reimplement */
        return g_direct_equal (v1, v2);
}

/**
 * polkit_hash_str_hash_func:
 * @key: the key
 *
 * Converts a string to a hash value.
 *
 * Returns: a hash value corresponding to the key
 *
 * Since: 0.7
 */
polkit_uint32_t
polkit_hash_str_hash_func (const void *key)
{
        const char *p;
        polkit_uint32_t hash;

        hash = 0;
        for (p = key; *p != '\0'; p++)
                hash = hash * 617 ^ *p;

        return hash;
}

/**
 * polkit_hash_str_equal_func:
 * @v1: first value
 * @v2: second value
 *
 * Compares two strings and return #TRUE if they are equal.
 *
 * Returns: #TRUE only if the values are equal
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_hash_str_equal_func (const void *v1, const void *v2)
{
        return strcmp (v1, v2) == 0;
}

/**
 * polkit_hash_str_copy:
 * @p: void pointer to string
 *
 * Similar to p_strdup() except for types.
 *
 * Returns: a void pointer to a copy or #NULL on OOM
 */
void *
polkit_hash_str_copy (const void *p)
{
        return (void *) p_strdup ((const char *) p);
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_it1 (PolKitHash *hash, void *key, void *value, void *user_data)
{
        int *count = (int *) user_data;
        *count += 1;
        return FALSE;
}

static polkit_bool_t
_it2 (PolKitHash *hash, void *key, void *value, void *user_data)
{
        int *count = (int *) user_data;
        *count += 1;
        return TRUE;
}

static polkit_bool_t
_run_test (void)
{
        int count;
        PolKitHash *h;
        polkit_bool_t found;

        /* string hash tables */
        if ((h = polkit_hash_new (polkit_hash_str_hash_func, polkit_hash_str_equal_func, 
                                  polkit_hash_str_copy, polkit_hash_str_copy,
                                  p_free, p_free)) != NULL) {
                int n;
                char *key;
                char *value;
                char *test_data[] = {"key1", "val1",
                                     "key2", "val2",
                                     "key3", "val3",
                                     "key4", "val4",
                                     "key5", "val5",
                                     "key6", "val6",
                                     "key7", "val7",
                                     "key8", "val8",
                                     "key9", "val9",
                                     "key10", "val10",
                                     "key11", "val11",
                                     "key12", "val12",
                                     NULL};

                /* first insert the values */
                for (n = 0; test_data [n*2] != NULL; n++) {
                        if (!polkit_hash_insert (h, test_data [n*2], test_data [n*2 + 1])) {
                                goto oom;
                        }
                }

                /* then check that we can look them up */
                for (n = 0; test_data [n*2] != NULL; n++) {
                        key = test_data [n*2];
                        value = polkit_hash_lookup (h, test_data[n*2], &found);

                        g_assert (found && strcmp (value, test_data[n*2 + 1]) == 0);
                }

                /* lookup unknown key */
                g_assert (polkit_hash_lookup (h, "unknown", &found) == NULL && !found);

                /* replace key */
                if (key != NULL) {
                        if (polkit_hash_insert (h, "key1", "val1-replaced")) {
                                /* check for replaced value */
                                value = polkit_hash_lookup (h, "key1", &found);
                                g_assert (found && value != NULL && strcmp (value, "val1-replaced") == 0);
                        }
                }

                count = 0;
                g_assert (polkit_hash_foreach (h, _it1, &count) == FALSE);
                g_assert (count == ((sizeof (test_data) / sizeof (char *) - 1) / 2));
                count = 0;
                g_assert (polkit_hash_foreach (h, _it2, &count) == TRUE);
                g_assert (count == 1);
                
                polkit_hash_ref (h);
                polkit_hash_unref (h);
        oom:

                polkit_hash_unref (h);
        }

        /* direct hash tables */
        if ((h = polkit_hash_new (polkit_hash_direct_hash_func, polkit_hash_direct_equal_func, 
                                  NULL, NULL, 
                                  NULL, NULL)) != NULL) {
                if (polkit_hash_insert (h, h, h)) {
                        g_assert ((polkit_hash_lookup (h, h, &found) == h) && found);
                        if (polkit_hash_insert (h, h, NULL)) {
                                g_assert (polkit_hash_lookup (h, h, &found) == NULL && found);
                        }
                }
                polkit_hash_unref (h);
        }

        return TRUE;
}

PolKitTest _test_hash = {
        "polkit_hash",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

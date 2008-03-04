/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-hash.c : Hash tables
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kit/kit-memory.h>
#include <kit/kit-hash.h>
#include <kit/kit-test.h>

/**
 * SECTION:kit-hash
 * @title: Hash tables
 * @short_description: Hash tables
 *
 * This class provides support for hash tables.
 **/

struct _KitHashNode;

typedef struct _KitHashNode {
        void *key;
        void *value;
        struct _KitHashNode *next;
} KitHashNode;


/**
 * KitHash:
 *
 * The #KitHash structure not be accessed directly.
 */
struct _KitHash
{
        int refcount;

        int num_top_nodes;
        KitHashNode **top_nodes;

        KitHashFunc  hash_func;
        KitEqualFunc key_equal_func;
        KitCopyFunc  key_copy_func;
        KitCopyFunc  value_copy_func;
        KitFreeFunc  key_destroy_func;
        KitFreeFunc  value_destroy_func;
};

/**
 * kit_hash_new:
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
 */
KitHash *
kit_hash_new (KitHashFunc  hash_func,
              KitEqualFunc key_equal_func,
              KitCopyFunc  key_copy_func,
              KitCopyFunc  value_copy_func,
              KitFreeFunc  key_destroy_func,
              KitFreeFunc  value_destroy_func)
{
        KitHash *h;

        kit_return_val_if_fail (hash_func != NULL, NULL);
        kit_return_val_if_fail (key_equal_func != NULL, NULL);

        h = kit_new0 (KitHash, 1);
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
        h->top_nodes = kit_new0 (KitHashNode*, h->num_top_nodes);
        if (h->top_nodes == NULL)
                goto error;

        return h;
error:
        if (h != NULL)
                kit_hash_unref (h);
        return NULL;
}

/**
 * kit_hash_ref:
 * @hash: the hash table
 *
 * Increase reference count.
 *
 * Returns: the hash table
 */
KitHash *
kit_hash_ref (KitHash *hash)
{
        kit_return_val_if_fail (hash != NULL, hash);
        hash->refcount++;
        return hash;
}

/**
 * kit_hash_unref:
 * @hash: the hash table
 *
 * Decrease reference count. If reference count drop to zero the hash
 * table is freed.
 */
void
kit_hash_unref (KitHash *hash)
{
        kit_return_if_fail (hash != NULL);

        hash->refcount--;
        if (hash->refcount > 0) 
                return;

        if (hash->top_nodes != NULL) {
                int n;

                for (n = 0; n < hash->num_top_nodes; n++) {
                        KitHashNode *node;
                        KitHashNode *next;
                        
                        for (node = hash->top_nodes[n]; node != NULL; node = next) {
                                if (hash->key_destroy_func != NULL)
                                        hash->key_destroy_func (node->key);
                                if (hash->value_destroy_func != NULL)
                                        hash->value_destroy_func (node->value);
                                next = node->next;
                                kit_free (node);
                        }
                }
        }

        kit_free (hash->top_nodes);
        kit_free (hash);
}

/**
 * kit_hash_insert:
 * @hash: the hash table
 * @key: key to insert
 * @value: value to insert
 *
 * Inserts a new key and value into a hash table. If the key already
 * exists in the hash table it's current value is replaced with the
 * new value.
 *
 * Returns: #TRUE unless OOM
 */
kit_bool_t 
kit_hash_insert (KitHash *hash,
                 void *key,
                 void *value)
{
        int bucket;
        KitHashNode **nodep;
        KitHashNode *node;
        void *key_copy;
        void *value_copy;

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

        node = kit_new0 (KitHashNode, 1);
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
 * kit_hash_lookup:
 * @hash: the hash table
 * @key: key to look up
 * @found: if not #NULL, will return #TRUE only if the key was found in the hash table
 *
 * Look up a value in the hash table.
 *
 * Returns: the value; caller shall not free/unref this value
 */
void *
kit_hash_lookup (KitHash *hash, void *key, kit_bool_t *found)
{
        int bucket;
        void *value;
        KitHashNode *node;

        value = NULL;
        if (found != NULL)
                *found = FALSE;

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
 * kit_hash_foreach:
 * @hash: the hash table
 * @cb: callback function
 * @user_data: user data
 *
 * Iterate over all elements in a hash table
 *
 * Returns: #TRUE only if the callback short-circuited the iteration
 */
kit_bool_t
kit_hash_foreach (KitHash *hash, KitHashForeachFunc cb, void *user_data)
{
        int n;

        kit_return_val_if_fail (hash != NULL, FALSE);
        kit_return_val_if_fail (cb != NULL, FALSE);

        for (n = 0; n < hash->num_top_nodes; n++) {
                KitHashNode *node;

                for (node = hash->top_nodes[n]; node != NULL; node = node->next) {
                        if (cb (hash, node->key, node->value, user_data))
                                return TRUE;
                }
        }

        return FALSE;
}

/**
 * kit_hash_foreach_remove:
 * @hash: the hash table
 * @cb: callback function
 * @user_data: user data
 *
 * Iterate over all elements in a hash table. If @cb returns %TRUE,
 * the element will be removed.
 *
 * Returns: Number of key/value pairs removed
 */
size_t
kit_hash_foreach_remove (KitHash *hash, KitHashForeachFunc cb, void *user_data)
{
        int n;
        size_t num_rem;

        kit_return_val_if_fail (hash != NULL, FALSE);
        kit_return_val_if_fail (cb != NULL, FALSE);

        num_rem = 0;

        for (n = 0; n < hash->num_top_nodes; n++) {
                KitHashNode *node;
                KitHashNode *node_next;
                KitHashNode **prev_node_next;

                prev_node_next = &(hash->top_nodes[n]);

                for (node = hash->top_nodes[n]; node != NULL; node = node_next) {
                        node_next = node->next;

                        if (cb (hash, node->key, node->value, user_data)) {

                                if (hash->key_destroy_func != NULL)
                                        hash->key_destroy_func (node->key);
                                if (hash->value_destroy_func != NULL)
                                        hash->value_destroy_func (node->value);
                                kit_free (node);

                                *prev_node_next = node_next;                                
                                num_rem++;
                        } else {
                                prev_node_next = &(node->next);
                        }
                }
        }

        return num_rem;
}


/**
 * kit_hash_direct_hash_func:
 * @key: the key
 *
 * Converts a pointer to a hash value.
 *
 * Returns: a hash value corresponding to the key
 */
uint32_t 
kit_hash_direct_hash_func (const void *key)
{
        return (uint32_t) key;
}

/**
 * kit_hash_direct_equal_func:
 * @v1: first value
 * @v2: second value
 *
 * Compares two pointers and return #TRUE if they are equal (same address).
 *
 * Returns: #TRUE only if the values are equal
 */
kit_bool_t
kit_hash_direct_equal_func (const void *v1, const void *v2)
{
        return v1 == v2;
}

/**
 * kit_hash_str_hash_func:
 * @key: the key
 *
 * Converts a string to a hash value.
 *
 * Returns: a hash value corresponding to the key
 */
uint32_t
kit_hash_str_hash_func (const void *key)
{
        const char *p;
        uint32_t hash;

        hash = 0;
        for (p = key; *p != '\0'; p++)
                hash = hash * 617 ^ *p;

        return hash;
}

/**
 * kit_hash_str_equal_func:
 * @v1: first value
 * @v2: second value
 *
 * Compares two strings and return #TRUE if they are equal.
 *
 * Returns: #TRUE only if the values are equal
 */
kit_bool_t
kit_hash_str_equal_func (const void *v1, const void *v2)
{
        return strcmp (v1, v2) == 0;
}

/**
 * kit_hash_str_copy:
 * @p: void pointer to string
 *
 * Similar to kit_strdup() except for types.
 *
 * Returns: a void pointer to a copy or #NULL on OOM
 */
void *
kit_hash_str_copy (const void *p)
{
        return (void *) kit_strdup ((const char *) p);
}

#ifdef KIT_BUILD_TESTS

static kit_bool_t
_it1 (KitHash *hash, void *key, void *value, void *user_data)
{
        int *count = (int *) user_data;
        *count += 1;
        return FALSE;
}

static kit_bool_t
_it2 (KitHash *hash, void *key, void *value, void *user_data)
{
        int *count = (int *) user_data;
        *count += 1;
        return TRUE;
}

static kit_bool_t
_it_sum (KitHash *hash, void *key, void *value, void *user_data)
{
        int *count = (int *) user_data;
        *count += (int) value;
        return FALSE;
}

static kit_bool_t
_it_rem (KitHash *hash, void *key, void *value, void *user_data)
{
        if (strlen ((char *) key) > 4)
                return TRUE;
        else
                return FALSE;
}

static kit_bool_t
_run_test (void)
{
        int count;
        KitHash *h;
        kit_bool_t found;

        /* string hash tables */
        if ((h = kit_hash_new (kit_hash_str_hash_func, kit_hash_str_equal_func, 
                                  kit_hash_str_copy, kit_hash_str_copy,
                                  kit_free, kit_free)) != NULL) {
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
                        if (!kit_hash_insert (h, test_data [n*2], test_data [n*2 + 1])) {
                                goto oom;
                        }
                }

                /* then check that we can look them up */
                for (n = 0; test_data [n*2] != NULL; n++) {
                        key = test_data [n*2];
                        value = kit_hash_lookup (h, test_data[n*2], &found);

                        kit_assert (found && strcmp (value, test_data[n*2 + 1]) == 0);
                }

                /* lookup unknown key */
                kit_assert (kit_hash_lookup (h, "unknown", &found) == NULL && !found);

                /* replace key */
                if (key != NULL) {
                        if (kit_hash_insert (h, "key1", "val1-replaced")) {
                                /* check for replaced value */
                                value = kit_hash_lookup (h, "key1", &found);
                                kit_assert (found && value != NULL && strcmp (value, "val1-replaced") == 0);
                        }
                }

                count = 0;
                kit_assert (kit_hash_foreach (h, _it1, &count) == FALSE);
                kit_assert (count == ((sizeof (test_data) / sizeof (char *) - 1) / 2));
                count = 0;
                kit_assert (kit_hash_foreach (h, _it2, &count) == TRUE);
                kit_assert (count == 1);
                
                kit_hash_ref (h);
                kit_hash_unref (h);
        oom:

                kit_hash_unref (h);
        }

        /* direct hash tables */
        if ((h = kit_hash_new (kit_hash_direct_hash_func, kit_hash_direct_equal_func, 
                                  NULL, NULL, 
                                  NULL, NULL)) != NULL) {
                if (kit_hash_insert (h, h, h)) {
                        kit_assert ((kit_hash_lookup (h, h, &found) == h) && found);
                        if (kit_hash_insert (h, h, NULL)) {
                                kit_assert (kit_hash_lookup (h, h, &found) == NULL && found);
                        }
                }
                kit_hash_unref (h);
        }

        /* remove */
        if ((h = kit_hash_new (kit_hash_str_hash_func, 
                               kit_hash_str_equal_func, 
                               kit_hash_str_copy, 
                               NULL,
                               kit_free, 
                               NULL)) != NULL) {        
                char *test_data[] = {"key1",
                                     "key2b",
                                     "key3",
                                     "key4",
                                     "key5b",
                                     "key6b",
                                     "key7",
                                     "key8",
                                     NULL};
                int n;
                int count;

                /* first insert the values */
                for (n = 0; test_data [n] != NULL; n++) {
                        if (!kit_hash_insert (h, test_data [n], (void *) (n + 1))) {
                                goto oom;
                        }
                }

                count = 0;
                kit_assert (kit_hash_foreach (h, _it_sum, &count) == FALSE);
                kit_assert (count == 1+2+3+4+5+6+7+8);

                kit_assert (kit_hash_foreach_remove (h, _it_rem, &count) == 3);
                count = 0;
                kit_assert (kit_hash_foreach (h, _it_sum, &count) == FALSE);
                kit_assert (count == 1+3+4+7+8);

                kit_hash_unref (h);
        }


        return TRUE;
}

KitTest _test_hash = {
        "kit_hash",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

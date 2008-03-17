/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-list.c : Doubly-linked lists
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
#include <kit/kit.h>
#include "kit-test.h"

/**
 * SECTION:kit-list
 * @title: Doubly-linked lists
 * @short_description: Doubly-linked lists
 *
 * This class provides support for doubly-linked lists.
 **/

/**
 * kit_list_append:
 * @list: existing list or #NULL to create a new list
 * @data: data to append to the list
 *
 * Append an entry to a list.
 *
 * Returns: the head of the new list or #NULL on OOM
 */
KitList *
kit_list_append (KitList *list, void *data)
{
        KitList *l;
        KitList *j;
        
        for (j = list; j != NULL && j->next != NULL; j = j->next)
                ;
        
        l = kit_new0 (KitList, 1);
        if (l == NULL)
                goto oom;

        l->data = data;
        l->prev = j;
        
        if (j != NULL) {
                j->next = l;
        } else {
                list = l;
        }

        return list;
oom:
        return NULL;
}

/**
 * kit_list_copy:
 * @list: existing list
 *
 * Makes a copy of a list. It is not a deep copy.
 *
 * Returns: A copy of the new list or #NULL on OOM. Free with kit_list_free().
 **/
KitList *
kit_list_copy (KitList *list)
{
        KitList *l;
        KitList *j;

        l = NULL;
        for (j = list; j != NULL; j = j->next) {
                /* TODO: prepend, then reverse */
                l = kit_list_append (l, j->data);
                if (l == NULL)
                        goto oom;
        }

        return l;
oom:
        kit_list_free (l);
        return NULL;
}

/**
 * kit_list_prepend:
 * @list: existing list or #NULL to create a new list
 * @data: data to prepend to the list
 *
 * Prepend an entry to a list.
 *
 * Returns: the head of the new list or #NULL on OOM
 */
KitList *
kit_list_prepend (KitList *list, void *data)
{
        KitList *l;

        l = kit_new0 (KitList, 1);
        if (l == NULL)
                goto oom;

        l->next = list;
        l->data = data;
        if (list != NULL) {
                list->prev = l;
        }

oom:
        return l;
}

/**
 * kit_list_delete_link:
 * @list: existing list, cannot be #NULL
 * @link: link to delete, cannot be #NULL
 *
 * Delete a link from a list.
 *
 * Returns: the new head of the list or #NULL if the list is empty after deletion.
 */
KitList *
kit_list_delete_link (KitList *list, KitList *link)
{
        KitList *ret;

        kit_return_val_if_fail (list != NULL, NULL);
        kit_return_val_if_fail (link != NULL, NULL);

        if (list == link)
                ret = link->next;
        else
                ret = list;

        if (link->prev != NULL) {
                link->prev->next = link->next;
        }

        if (link->next != NULL) {
                link->next->prev = link->prev;
        }

        kit_free (link);

        return ret;
}

/**
 * kit_list_free:
 * @list: the list
 *
 * Frees all links in a list
 */
void
kit_list_free (KitList *list)
{
        KitList *l;
        KitList *j;

        for (l = list; l != NULL; l = j) {
                j = l->next;
                kit_free (l);
        }
}

/**
 * kit_list_length:
 * @list: the list
 *
 * Compute the length of a list.
 *
 * Returns: Number of entries in list
 */
size_t
kit_list_length (KitList *list)
{
        ssize_t n;
        KitList *l;

        n = 0;
        for (l = list; l != NULL; l = l->next)
                n++;

        return n;
}

/**
 * kit_list_foreach:
 * @list: the list
 * @func: callback function
 * @user_data: user data to pass to callback
 *
 * Iterate over all entries in a list.
 *
 * Returns: #TRUE only if the callback short-circuited the iteration
 */
kit_bool_t 
kit_list_foreach (KitList *list, KitListForeachFunc func, void *user_data)
{
        KitList *l;

        kit_return_val_if_fail (list != NULL, FALSE);
        kit_return_val_if_fail (func != NULL, FALSE);

        for (l = list; l != NULL; l = l->next) {
                if (func (list, l->data, user_data))
                        return TRUE;
        }
        
        return FALSE;
}


#ifdef KIT_BUILD_TESTS

typedef struct {
        int num;
        int result;
} _Closure;

static kit_bool_t 
_sum (KitList *list, void *data, void *user_data)
{
        _Closure *c = (_Closure*) user_data;

        c->result += ((int) data) * (c->num + 1);
        c->num += 1;

        return FALSE;
}

static kit_bool_t 
_sum2 (KitList *list, void *data, void *user_data)
{
        _Closure *c = (_Closure*) user_data;

        if (c->num == 2)
                return TRUE;

        c->result += ((int) data) * (c->num + 1);
        c->num += 1;

        return FALSE;
}

static kit_bool_t
_run_test (void)
{
        _Closure c;
        int items[] = {1, 2, 3, 4, 5};
        unsigned int num_items = sizeof (items) / sizeof (int);
        unsigned int n;
        KitList *l;
        KitList *j;

        l = NULL;
        for (n = 0; n < num_items; n++) {
                j = l;
                l = kit_list_prepend (l, (void *) items[n]);
                if (l == NULL)
                        goto oom;
        }

        kit_assert (kit_list_length (l) == num_items);
        c.num = 0;
        c.result = 0;
        kit_list_foreach (l, _sum, &c);
        kit_assert (c.result == 1*5 + 2*4 + 3*3 + 4*2 + 5*1);

        c.num = 0;
        c.result = 0;
        kit_list_foreach (l, _sum2, &c);
        kit_assert (c.result == 1*5 + 2*4);

        l = kit_list_delete_link (l, l);
        kit_assert (kit_list_length (l) == num_items - 1);
        c.num = 0;
        c.result = 0;
        kit_list_foreach (l, _sum, &c);
        kit_assert (c.result == 1*4 + 2*3 + 3*2 + 4*1);

        l = kit_list_delete_link (l, l->next);
        kit_assert (kit_list_length (l) == num_items - 2);
        c.num = 0;
        c.result = 0;
        kit_list_foreach (l, _sum, &c);
        kit_assert (c.result == 1*4 + 2*2 + 3*1);

        kit_list_free (l);

        l = NULL;
        for (n = 0; n < num_items; n++) {
                j = l;
                l = kit_list_append (l, (void *) items[n]);
                if (l == NULL)
                        goto oom;
        }

        c.num = 0;
        c.result = 0;
        kit_list_foreach (l, _sum, &c);
        kit_assert (c.result == 1*1 + 2*2 + 3*3 + 4*4 + 5*5);

        kit_list_free (l);

        return TRUE;
oom:
        kit_list_free (j);
        return TRUE;
}

KitTest _test_list = {
        "kit_list",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

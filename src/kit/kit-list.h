/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-list.h : Doubly-linked list
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

#if !defined (KIT_COMPILATION) && !defined(_KIT_INSIDE_KIT_H)
#error "Only <kit/kit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef KIT_LIST_H
#define KIT_LIST_H

#include <kit/kit.h>

KIT_BEGIN_DECLS

struct _KitList;
typedef struct _KitList KitList;

/**
 * KitList:
 * @data: the value passed in kit_list_append() and kit_list_prepend()
 * @next: the next element in the list or #NULL if this is the last element
 * @prev: the previous element in the list or #NULL if this is the last element
 *
 * Public members of the #KitList data structure
 */
struct _KitList {
        void *data;
        KitList *next;
        KitList *prev;
};

/**
 * KitListForeachFunc:
 * @list: the list
 * @data: data of link entry
 * @user_data: user data passed to kit_list_foreach()
 *
 * Type signature for callback function used in kit_list_foreach().
 *
 * Returns: Return #TRUE to short-circuit, e.g. stop the iteration.
 */
typedef kit_bool_t (*KitListForeachFunc) (KitList *list,
                                          void *data,
                                          void *user_data);

KitList    *kit_list_append      (KitList *list, void *data);
KitList    *kit_list_prepend     (KitList *list, void *data);
void        kit_list_free        (KitList *list);
KitList    *kit_list_delete_link (KitList *list, KitList *link);

size_t      kit_list_length      (KitList *list);
kit_bool_t  kit_list_foreach     (KitList *list, KitListForeachFunc func, void *user_data);
KitList    *kit_list_copy        (KitList *list);


KIT_END_DECLS

#endif /* KIT_LIST_H */



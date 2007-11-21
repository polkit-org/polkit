/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-list.h : Doubly-linked list
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


KIT_END_DECLS

#endif /* KIT_LIST_H */



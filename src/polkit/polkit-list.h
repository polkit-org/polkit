/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-list.h : Doubly-linked list
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

#ifndef POLKIT_LIST_H
#define POLKIT_LIST_H

#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

struct _PolKitList;
typedef struct _PolKitList PolKitList;

/**
 * PolKitList:
 * @data: the value passed in polkit_list_append() and polkit_list_prepend()
 * @next: the next element in the list or #NULL if this is the last element
 * @prev: the previous element in the list or #NULL if this is the last element
 *
 * Public members of the #PolKitList data structure
 *
 * Since: 0.7
 */
struct _PolKitList {
        void *data;
        PolKitList *next;
        PolKitList *prev;
};

/**
 * PolKitListForeachFunc:
 * @list: the list
 * @data: data of link entry
 * @user_data: user data passed to polkit_list_foreach()
 *
 * Type signature for callback function used in polkit_list_foreach().
 *
 * Returns: Return #TRUE to short-circuit, e.g. stop the iteration.
 *
 * Since: 0.7
 */
typedef polkit_bool_t (*PolKitListForeachFunc) (PolKitList *list,
                                                void *data,
                                                void *user_data);

PolKitList    *polkit_list_append      (PolKitList *list, void *data);
PolKitList    *polkit_list_prepend     (PolKitList *list, void *data);
void           polkit_list_free        (PolKitList *list);
PolKitList    *polkit_list_delete_link (PolKitList *list, PolKitList *link);

size_t         polkit_list_length      (PolKitList *list);
polkit_bool_t  polkit_list_foreach     (PolKitList *list, PolKitListForeachFunc func, void *user_data);


POLKIT_END_DECLS

#endif /* POLKIT_LIST_H */



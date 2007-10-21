/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-action.h : actions
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

#ifndef POLKIT_ACTION_H
#define POLKIT_ACTION_H

#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

struct _PolKitAction;
typedef struct _PolKitAction PolKitAction;

PolKitAction *polkit_action_new           (void);
PolKitAction *polkit_action_ref           (PolKitAction *action);
void          polkit_action_unref         (PolKitAction *action);
polkit_bool_t polkit_action_set_action_id (PolKitAction *action, const char  *action_id);
polkit_bool_t polkit_action_get_action_id (PolKitAction *action, char       **out_action_id);

void          polkit_action_debug         (PolKitAction *action);
polkit_bool_t polkit_action_validate      (PolKitAction *action);

polkit_bool_t polkit_action_validate_id   (const char   *action_id);

POLKIT_END_DECLS

#endif /* POLKIT_ACTION_H */



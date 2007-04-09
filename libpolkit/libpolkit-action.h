/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-action.h : actions
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

#ifndef LIBPOLKIT_ACTION_H
#define LIBPOLKIT_ACTION_H

#include <stdbool.h>

struct PolKitAction;
typedef struct PolKitAction PolKitAction;

/**
 * PolKitActionParamForeachFunc:
 * @action: the action
 * @key: key of parameter
 * @value: value of parameter
 * @user_data: user data
 *
 * Type for function used in libpolkit_action_param_foreach().
 **/
typedef void (*PolKitActionParamForeachFunc) (PolKitAction *action, 
                                              const char *key, 
                                              const char *value, 
                                              void *user_data);

PolKitAction *libpolkit_action_new           (void);
PolKitAction *libpolkit_action_ref           (PolKitAction *action);
void          libpolkit_action_unref         (PolKitAction *action);
void          libpolkit_action_set_action_id (PolKitAction *action, const char  *action_id);
bool          libpolkit_action_get_action_id (PolKitAction *action, char       **out_action_id);

void          libpolkit_action_set_param     (PolKitAction *action, const char *key, const char *value);
const char   *libpolkit_action_get_param     (PolKitAction *action, const char *key);
void          libpolkit_action_param_foreach (PolKitAction *action, PolKitActionParamForeachFunc cb, void *user_data);

void          libpolkit_action_debug         (PolKitAction *action);

#endif /* LIBPOLKIT_ACTION_H */



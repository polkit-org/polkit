/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-config.h : Configuration file
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

#ifndef POLKIT_CONFIG_H
#define POLKIT_CONFIG_H

#include <polkit/polkit-error.h>
#include <polkit/polkit-types.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-context.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>

struct PolKitConfig;
typedef struct PolKitConfig PolKitConfig;

PolKitConfig  *polkit_config_new                    (PolKitError **error);
PolKitConfig  *polkit_config_ref                    (PolKitConfig *pk_config);
void           polkit_config_unref                  (PolKitConfig *pk_config);

PolKitResult
polkit_config_can_session_do_action                 (PolKitConfig   *pk_config,
                                                     PolKitAction    *action,
                                                     PolKitSession   *session);

PolKitResult
polkit_config_can_caller_do_action                  (PolKitConfig   *pk_config,
                                                     PolKitAction    *action,
                                                     PolKitCaller    *caller);

#endif /* POLKIT_CONFIG_H */



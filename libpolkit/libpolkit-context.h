/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-context.h : PolicyKit context
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

#ifndef LIBPOLKIT_CONTEXT_H
#define LIBPOLKIT_CONTEXT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

struct PolKitContext;
typedef struct PolKitContext PolKitContext;

/**
 * PolKitContextConfigChangedCB:
 * @pk_context: PolicyKit context
 * @user_data: user data
 *
 * See libpolkit_context_set_config_changed() for details.
 */
typedef void (*PolKitContextConfigChangedCB) (PolKitContext  *pk_context,
                                              gpointer        user_data);

PolKitContext *libpolkit_context_new                (void);
PolKitContext *libpolkit_context_ref                (PolKitContext                *pk_context);
void           libpolkit_context_set_config_changed (PolKitContext                *pk_context, 
                                                     PolKitContextConfigChangedCB  cb, 
                                                     gpointer                      user_data);
void           libpolkit_context_unref              (PolKitContext                *pk_context);


#endif /* LIBPOLKIT_CONTEXT_H */



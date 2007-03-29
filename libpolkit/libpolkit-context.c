/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-context.c : context for PolicyKit
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "libpolkit-context.h"

/**
 * SECTION:libpolkit-context
 * @short_description: Context.
 *
 * This class is used to represent the interface to PolicyKit.
 **/

/**
 * PolKitContext:
 *
 * Context object for users of PolicyKit.
 **/
struct PolKitContext
{
        int refcount;
        PolKitContextConfigChangedCB config_changed_cb;
        gpointer config_changed_user_data;
};

/**
 * libpolkit_context_new:
 * 
 * Create a new context.
 * 
 * Returns: the new context object
 **/
PolKitContext *
libpolkit_context_new (void)
{
        PolKitContext *pk_context;
        pk_context = g_new0 (PolKitContext, 1);
        pk_context->refcount = 1;
        return pk_context;
}

/**
 * libpolkit_context_ref:
 * @pk_context: the context object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitContext *
libpolkit_context_ref (PolKitContext *pk_context)
{
        g_return_val_if_fail (pk_context != NULL, pk_context);
        pk_context->refcount++;
        return pk_context;
}

/**
 * libpolkit_context_unref:
 * @pk_context: the context object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_context_unref (PolKitContext *pk_context)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->refcount--;
        if (pk_context->refcount > 0) 
                return;
        g_free (pk_context);
}

/**
 * libpolkit_context_set_config_changed:
 * @pk_context: the context object
 * @cb: the callback to invoke
 * @user_data: user data to pass to the callback
 * 
 * Register the callback function for when configuration changes.
 * Mechanisms should use this callback to e.g. reconfigure all
 * permissions / acl's they have set in response to policy decisions
 * made from information provided by PolicyKit.
 **/
void
libpolkit_context_set_config_changed (PolKitContext                *pk_context, 
                                      PolKitContextConfigChangedCB cb, 
                                      gpointer                     user_data)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->config_changed_cb = cb;
        pk_context->config_changed_user_data = user_data;
}

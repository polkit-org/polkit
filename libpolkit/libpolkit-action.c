/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-action.c : action
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
#include "libpolkit-debug.h"
#include "libpolkit-action.h"

/**
 * SECTION:libpolkit-action
 * @short_description: Actions.
 *
 * This class is used to represent an action. TODO: describe what a action really is.
 **/

/**
 * PolKitAction:
 *
 * Objects of this class are used to record information about an action.
 **/
struct PolKitAction
{
        int refcount;
        char *id;
        GHashTable *params;
};

/**
 * libpolkit_action_new:
 * 
 * Create a new #PolKitAction object.
 * 
 * Returns: the new object
 **/
PolKitAction *
libpolkit_action_new (void)
{
        PolKitAction *action;
        action = g_new0 (PolKitAction, 1);
        action->refcount = 1;
        action->params = g_hash_table_new_full (g_str_hash, 
                                                g_str_equal,
                                                g_free,
                                                g_free);
        return action;
}

/**
 * libpolkit_action_ref:
 * @action: the action object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitAction *
libpolkit_action_ref (PolKitAction *action)
{
        g_return_val_if_fail (action != NULL, action);
        action->refcount++;
        return action;
}

/**
 * libpolkit_action_unref:
 * @action: the action object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_action_unref (PolKitAction *action)
{
        g_return_if_fail (action != NULL);
        action->refcount--;
        if (action->refcount > 0) 
                return;
        g_free (action->id);
        g_hash_table_destroy (action->params);
        g_free (action);
}

/**
 * libpolkit_action_set_action_id:
 * @action: the action object
 * @action_id: action identifier
 * 
 * Set the action identifier
 **/
void
libpolkit_action_set_action_id (PolKitAction *action, const char  *action_id)
{
        g_return_if_fail (action != NULL);
        if (action->id != NULL)
                g_free (action->id);
        action->id = g_strdup (action_id);
}

/**
 * libpolkit_action_get_action_id:
 * @action: the action object
 * @out_action_id: Returns the action identifier. The caller shall not free this string.
 * 
 * Get the action identifier.
 * 
 * Returns: TRUE iff the value was returned.
 **/
bool
libpolkit_action_get_action_id (PolKitAction *action, char **out_action_id)
{
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (out_action_id != NULL, FALSE);
        if (action->id == NULL)
                return FALSE;
        *out_action_id = action->id;
        return TRUE;
}

/**
 * libpolkit_action_debug:
 * @action: the object
 * 
 * Print debug details
 **/
void
libpolkit_action_debug (PolKitAction *action)
{
        g_return_if_fail (action != NULL);
        _pk_debug ("PolKitAction: refcount=%d id=%s", action->refcount, action->id);
}

/**
 * libpolkit_action_set_param:
 * @action: the action
 * @key: key
 * @value: value
 * 
 * Set a parameter (a key/value pair) associated with the action.
 **/
void
libpolkit_action_set_param (PolKitAction *action, const char *key, const char *value)
{
        g_return_if_fail (action != NULL);
        g_return_if_fail (key != NULL);

        g_hash_table_insert (action->params, g_strdup (key), g_strdup (value));
}

/**
 * libpolkit_action_get_param:
 * @action: the action
 * @key: key
 * 
 * Get a parameter (a key/value pair) associated with the action.
 * 
 * Returns: the value or #NULL if the parameter wasn't set.
 **/
const char *
libpolkit_action_get_param (PolKitAction *action, const char *key)
{
        const char *value;

        g_return_val_if_fail (action != NULL, NULL);
        g_return_val_if_fail (key != NULL, NULL);

        value = g_hash_table_lookup (action->params, key);
        return value;
}

typedef struct {
        PolKitAction *action;
        PolKitActionParamForeachFunc cb;
        void *user_data;
} HashClosure;

static void
_hash_cb (gpointer key, gpointer value, gpointer user_data)
{
        HashClosure *data = user_data;
        data->cb (data->action, key, value, data->user_data);
}

/**
 * libpolkit_action_param_foreach:
 * @action: the action
 * @cb: function to call
 * @user_data: user data
 * 
 * Calls the given function for each parameter on the object.
 **/
void
libpolkit_action_param_foreach (PolKitAction *action, PolKitActionParamForeachFunc cb, void *user_data)
{
        HashClosure data;

        g_return_if_fail (action != NULL);
        g_return_if_fail (cb != NULL);

        data.action = action;
        data.cb = cb;
        data.user_data = user_data;
        g_hash_table_foreach (action->params, _hash_cb, &data);
}


/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-action.c : action
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
#include "polkit-debug.h"
#include "polkit-action.h"
#include "polkit-utils.h"

/**
 * SECTION:polkit-action
 * @title: Actions
 * @short_description: Models what a caller is attempting to do.
 *
 * This class is used to represent a PolicyKit action.
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
 * polkit_action_new:
 * 
 * Create a new #PolKitAction object.
 * 
 * Returns: the new object
 **/
PolKitAction *
polkit_action_new (void)
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
 * polkit_action_ref:
 * @action: the action object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitAction *
polkit_action_ref (PolKitAction *action)
{
        g_return_val_if_fail (action != NULL, action);
        action->refcount++;
        return action;
}

/**
 * polkit_action_unref:
 * @action: the action object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_action_unref (PolKitAction *action)
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
 * polkit_action_set_action_id:
 * @action: the action object
 * @action_id: action identifier
 * 
 * Set the action identifier
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_action_set_action_id (PolKitAction *action, const char  *action_id)
{
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (_pk_validate_identifier (action_id), FALSE);
        if (action->id != NULL)
                g_free (action->id);
        action->id = g_strdup (action_id);
        return TRUE;
}

/**
 * polkit_action_get_action_id:
 * @action: the action object
 * @out_action_id: Returns the action identifier. The caller shall not free this string.
 * 
 * Get the action identifier.
 * 
 * Returns: TRUE iff the value was returned.
 **/
polkit_bool_t
polkit_action_get_action_id (PolKitAction *action, char **out_action_id)
{
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (out_action_id != NULL, FALSE);
        if (action->id == NULL)
                return FALSE;
        *out_action_id = action->id;
        return TRUE;
}

/**
 * polkit_action_debug:
 * @action: the object
 * 
 * Print debug details
 **/
void
polkit_action_debug (PolKitAction *action)
{
        g_return_if_fail (action != NULL);
        _pk_debug ("PolKitAction: refcount=%d id=%s", action->refcount, action->id);
}

/**
 * polkit_action_validate_id:
 * @action_id: the action identifier to validate
 * 
 * Validate whether an action identifier is well formed. To be well
 * formed, an action identifier needs to start with a lower case ASCII
 * character and can only contain the characters "[a-z][0-9].-".
 * 
 * Returns: #TRUE iff the action identifier is well formed
 **/
polkit_bool_t
polkit_action_validate_id (const char *action_id)
{
        int n;

        g_return_val_if_fail (action_id != NULL, FALSE);

        /* validate that the form of the action identifier is correct */
        if (!g_ascii_islower (action_id[0]))
                goto malformed;

        for (n = 1; action_id[n] != '\0'; n++) {
                if (! (g_ascii_islower (action_id[n]) ||
                       g_ascii_isdigit (action_id[n]) ||
                       action_id[n] == '.' ||
                       action_id[n] == '-'))
                        goto malformed;
        }

        return TRUE;

malformed:
        return FALSE;
}

/**
 * polkit_action_validate:
 * @action: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 **/
polkit_bool_t
polkit_action_validate (PolKitAction *action)
{
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (action->id != NULL, FALSE);

        return polkit_action_validate_id (action->id);
}




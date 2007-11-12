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
#include <ctype.h>

#include "polkit-debug.h"
#include "polkit-action.h"
#include "polkit-utils.h"
#include "polkit-utils.h"
#include "polkit-private.h"
#include "polkit-test.h"

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
struct _PolKitAction
{
        int refcount;
        char *id;
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
        action = kit_new0 (PolKitAction, 1);
        if (action == NULL)
                goto out;
        action->refcount = 1;
out:
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
        kit_return_val_if_fail (action != NULL, action);
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
        kit_return_if_fail (action != NULL);
        action->refcount--;
        if (action->refcount > 0) 
                return;
        kit_free (action->id);
        kit_free (action);
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
        kit_return_val_if_fail (action != NULL, FALSE);
        kit_return_val_if_fail (polkit_action_validate_id (action_id), FALSE);
        if (action->id != NULL)
                kit_free (action->id);
        action->id = kit_strdup (action_id);
        if (action->id == NULL)
                return FALSE;

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
        kit_return_val_if_fail (action != NULL, FALSE);
        kit_return_val_if_fail (out_action_id != NULL, FALSE);
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
        kit_return_if_fail (action != NULL);
        _pk_debug ("PolKitAction: refcount=%d id=%s", action->refcount, action->id);
}

/**
 * polkit_action_validate_id:
 * @action_id: the action identifier to validate
 * 
 * Validate whether an action identifier is well formed. To be well
 * formed, an action identifier needs to start with a lower case ASCII
 * character and can only contain the characters "[a-z][0-9].-". It
 * must be less than or equal 256 bytes in length including the
 * terminating NUL character.
 * 
 * Returns: #TRUE iff the action identifier is well formed
 **/
polkit_bool_t
polkit_action_validate_id (const char *action_id)
{
        int n;

        kit_return_val_if_fail (action_id != NULL, FALSE);

        /* validate that the form of the action identifier is correct */
        if (!islower (action_id[0]))
                goto malformed;

        for (n = 1; action_id[n] != '\0'; n++) {
                if (n >= 255)
                        goto malformed;

                if (! (islower (action_id[n]) ||
                       isdigit (action_id[n]) ||
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
        kit_return_val_if_fail (action != NULL, FALSE);
        kit_return_val_if_fail (action->id != NULL, FALSE);

        return polkit_action_validate_id (action->id);
}



#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        int n;
        char *valid_action_ids[]   = {"org.example.action",
                                      "org.example.action-foo", 
                                      "org.example.action-foo.42", 
                                      "org.example.42-.foo", 
                                      "t0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                                      NULL};
        char *invalid_action_ids[] = {"1org.example.action", 
                                      ".org.example.action", 
                                      "-org.example.action", 
                                      "org.example.action_foo", 
                                      "org.example.something.that.is.too.long.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                      NULL};

        for (n = 0; valid_action_ids[n] != NULL; n++) {
                kit_assert (polkit_action_validate_id (valid_action_ids[n]));
        }

        for (n = 0; invalid_action_ids[n] != NULL; n++) {
                kit_assert (! polkit_action_validate_id (invalid_action_ids[n]));
        }

        PolKitAction *a;
        char *s;
        a = polkit_action_new ();
        if (a == NULL) {
                /* OOM */
        } else {

                kit_assert (! polkit_action_get_action_id (a, &s));

                if (!polkit_action_set_action_id (a, "org.example.action")) {
                        /* OOM */
                } else {
                        kit_assert (polkit_action_validate (a));
                        polkit_action_ref (a);
                        kit_assert (polkit_action_validate (a));
                        polkit_action_unref (a);
                        kit_assert (polkit_action_validate (a));

                        if (!polkit_action_set_action_id (a, "org.example.action2")) {
                                /* OOM */
                        } else {
                                kit_assert (polkit_action_validate (a));
                                kit_assert (polkit_action_get_action_id (a, &s));
                                kit_assert (strcmp (s, "org.example.action2") == 0);
                                polkit_action_debug (a);
                        }
                }

                polkit_action_unref (a);
        }
        

        return TRUE;
}

KitTest _test_action = {
        "polkit_action",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

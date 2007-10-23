/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization.c : Represents an entry in the authorization
 * database
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
#include "polkit-authorization.h"
#include "polkit-utils.h"

/**
 * SECTION:polkit-authorization
 * @title: Authorization Entry
 * @short_description: An entry in the autothorization database
 *
 * This class is used to represent entries in the authorization
 * database.
 *
 * Since: 0.7
 **/

/**
 * PolKitAuthorization:
 *
 * Objects of this class are used to represent entries in the
 * authorization database.
 *
 * Since: 0.7
 **/
struct _PolKitAuthorization
{
        int refcount;
};

/**
 * polkit_authorization_ref:
 * @authorization: the authorization object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 *
 * Since: 0.7
 **/
PolKitAuthorization *
polkit_authorization_ref (PolKitAuthorization *authorization)
{
        g_return_val_if_fail (authorization != NULL, authorization);
        authorization->refcount++;
        return authorization;
}

/**
 * polkit_authorization_unref:
 * @authorization: the authorization object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 *
 * Since: 0.7
 **/
void
polkit_authorization_unref (PolKitAuthorization *authorization)
{
        g_return_if_fail (authorization != NULL);
        authorization->refcount--;
        if (authorization->refcount > 0) 
                return;
        g_free (authorization);
}

/**
 * polkit_authorization_debug:
 * @authorization: the object
 * 
 * Print debug details
 *
 * Since: 0.7
 **/
void
polkit_authorization_debug (PolKitAuthorization *authorization)
{
        g_return_if_fail (authorization != NULL);
        _pk_debug ("PolKitAuthorization: refcount=%d", authorization->refcount);
}

/**
 * polkit_authorization_validate:
 * @authorization: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 *
 * Since: 0.7
 **/
polkit_bool_t
polkit_authorization_validate (PolKitAuthorization *authorization)
{
        g_return_val_if_fail (authorization != NULL, FALSE);

        return TRUE;
}

/**
 * polkit_authorization_get_action_id:
 * @authorization: the object
 *
 * Get the action this authorization is for
 *
 * Returns: the #PolKitAction object. Caller should not unref the
 * object; it is owned by the #PolKitAuthorization instance and will
 * by unreffed when that object is unreffed.
 *
 * Since: 0.7
 */ 
PolKitAction *
polkit_authorization_get_action_id (PolKitAuthorization *authorization)
{
        return NULL;
}

/**
 * polkit_authorization_get_scope:
 * @authorization: the object
 *
 * Get the scope of the authorization; e.g. whether it's confined to a
 * single process, a single session or can be retained indefinitely.
 *
 * Returns: the scope
 *
 * Since: 0.7
 */ 
PolKitAuthorizationScope
polkit_authorization_get_scope (PolKitAuthorization *authorization)
{
        return 0;
}

/**
 * polkit_authorization_scope_process_get_pid:
 * @authorization: the object
 * @out_pid: return location
 * @out_pid_start_time: return location
 *
 * If scope is #POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT or
 * #POLKIT_AUTHORIZATION_SCOPE_PROCESS, get information about what
 * process the authorization is confined to. 
 *
 * As process identifiers can be recycled, the start time of the
 * process (the unit is not well-defined; on Linux it's the number of
 * milliseconds since the system was started) is also returned.
 *
 * Returns: #TRUE if information was returned
 *
 * Since: 0.7
 */ 
polkit_bool_t
polkit_authorization_scope_process_get_pid (PolKitAuthorization *authorization, 
                                            pid_t *out_pid, 
                                            polkit_uint64_t *out_pid_start_time)
{
        return FALSE;
}

/**
 * polkit_authorization_scope_session_get_ck_objref:
 * @authorization: the object
 * @out_ck_session_objref: return location
 *
 * Gets the ConsoleKit object path for the session the authorization
 * is confined to.
 *
 * Returns: #TRUE if information was returned
 *
 * Since: 0.7
 */ 
polkit_bool_t
polkit_authorization_scope_session_get_ck_objref (PolKitAuthorization *authorization, 
                                                  char **out_ck_session_objref)
{
        return FALSE;
}

/**
 * polkit_authorization_get_uid:
 * @authorization: the object
 *
 * Gets the UNIX user id for the user the authorization is confined
 * to.
 *
 * Returns: The UNIX user id for whom the authorization is confied to
 *
 * Since: 0.7
 */ 
uid_t
polkit_authorization_get_uid (PolKitAuthorization *authorization)
{
        return 0;
}

/**
 * polkit_authorization_get_time_of_grant:
 * @authorization: the object
 *
 * Returns the point in time the authorization was granted. The value
 * is UNIX time, e.g. number of seconds since the Epoch Jan 1, 1970
 * 0:00 UTC.
 *
 * Returns: #TRUE if information was returned
 *
 * Since: 0.7
 */ 
time_t
polkit_authorization_get_time_of_grant (PolKitAuthorization *authorization)
{
        return 0;
}

/**
 * polkit_authorization_was_granted_via_defaults:
 * @authorization: the object
 * @out_how: return location
 * @out_user_authenticated_as: return location
 *
 * Determine if the authorization was obtained by the user by
 * authenticating as himself or an administrator via the the
 * "defaults" section in the <literal>.policy</literal> file for the
 * action (e.g.  "allow_any", "allow_inactive", "allow_active").
 *
 * Compare with polkit_authorization_was_granted_explicitly() - only
 * one of these functions can return #TRUE.
 *
 * Returns: #TRUE if the authorization was obtained by the user
 * himself authenticating.
 *
 * Since: 0.7
 */ 
polkit_bool_t 
polkit_authorization_was_granted_via_defaults (PolKitAuthorization *authorization,
                                               PolKitResult *out_how,
                                               uid_t *out_user_authenticated_as)
{
        return FALSE;
}

/**
 * polkit_authorization_was_granted_explicitly:
 * @authorization: the object
 * @out_by_whom: return location
 *
 * Determine if the authorization was explicitly granted by a
 * sufficiently privileged user.
 *
 * Compare with polkit_authorization_was_granted_via_defaults() - only
 * one of these functions can return #TRUE.
 *
 * Returns: #TRUE if the authorization was explicitly granted by a
 * sufficiently privileger user.
 *
 * Since: 0.7
 */ 
polkit_bool_t 
polkit_authorization_was_granted_explicitly (PolKitAuthorization *authorization,
                                             uid_t *out_by_whom)
{
        return FALSE;
}

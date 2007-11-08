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
#include "polkit-private.h"

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

        char *entry_in_auth_file;

        PolKitAuthorizationScope scope;
        PolKitAuthorizationConstraint *constraint;

        char *action_id;
        uid_t uid;
        time_t when;
        uid_t authenticated_as_uid;

        pid_t pid;
        polkit_uint64_t pid_start_time;

        polkit_bool_t explicitly_granted;
        uid_t explicitly_granted_by;

        char *session_id;
};

const char *
_polkit_authorization_get_authfile_entry (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, NULL);
        return auth->entry_in_auth_file;
}

#ifdef POLKIT_AUTHDB_DEFAULT

PolKitAuthorization *
_polkit_authorization_new_for_uid (const char *entry_in_auth_file, uid_t uid)
{
        char **t;
        guint num_t;
        char *ep;
        PolKitAuthorization *auth;
        int n;

        g_return_val_if_fail (entry_in_auth_file != NULL, NULL);

        auth = g_new0 (PolKitAuthorization, 1);
        auth->refcount = 1;
        auth->entry_in_auth_file = g_strdup (entry_in_auth_file);
        auth->uid = uid;

        t = g_strsplit (entry_in_auth_file, ":", 0);
        num_t = g_strv_length (t);

/*
 * pid:
 *       grant_line = g_strdup_printf ("process:%d:%Lu:%s:%Lu:%d:%s\n", 
 *                                     caller_pid, 
 *                                     pid_start_time, 
 *                                     action_id,
 *                                     (polkit_uint64_t) now.tv_sec,
 *                                     user_authenticated_as,
 *                                     cbuf);
 */
        n = 1;

        if (strcmp (t[0], "process") == 0 ||
            strcmp (t[0], "process-one-shot") == 0) {
                if (num_t != 7)
                        goto error;

                if (strcmp (t[0], "process") == 0)
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_PROCESS;
                else
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT;

                auth->pid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->pid_start_time = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = g_strdup (t[n++]);

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->authenticated_as_uid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;
        }
/*
 *        grant_line = g_strdup_printf ("session:%s:%s:%Lu:%s:%d:%s\n", 
 *                                      session_objpath,
 *                                      action_id,
 *                                      (polkit_uint64_t) now.tv_sec,
 *                                      user_authenticated_as,
 *                                      cbuf);
 */
        else if (strcmp (t[0], "session") == 0) {
                if (num_t != 6)
                        goto error;

                auth->scope = POLKIT_AUTHORIZATION_SCOPE_SESSION;

                auth->session_id = g_strdup (t[n++]);

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = g_strdup (t[n++]);

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->authenticated_as_uid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;
        }

/*
 * always:
 *        grant_line = g_strdup_printf ("always:%s:%Lu:%s:%d:%s\n", 
 *                                      action_id,
 *                                      (polkit_uint64_t) now.tv_sec,
 *                                      user_authenticated_as,
 *                                      cbuf);
 *
 */
        else if (strcmp (t[0], "always") == 0) {
                if (num_t != 5)
                        goto error;

                auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = g_strdup (t[n++]);

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->authenticated_as_uid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;
        }
/*
 * grant:
 *                     "grant:%d:%s:%Lu:%d:%s\n",
 *                     action_id,
 *                     (polkit_uint64_t) now.tv_sec,
 *                     invoking_uid,
 *                     authc_str) >= (int) sizeof (grant_line)) {
 *
 */
        else if (strcmp (t[0], "grant") == 0) {

                if (num_t != 5)
                        goto error;

                auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;
                auth->explicitly_granted = TRUE;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = g_strdup (t[n++]);

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->explicitly_granted_by = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;

        } else {
                goto error;
        }

        g_strfreev (t);
        return auth;

error:
        g_warning ("Error parsing token %d from line '%s'", n, entry_in_auth_file);
        polkit_authorization_unref (auth);
        g_strfreev (t);
        return NULL;
}

#endif /* POLKIT_AUTHDB_DEFAULT */

/**
 * polkit_authorization_ref:
 * @auth: the authorization object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 *
 * Since: 0.7
 **/
PolKitAuthorization *
polkit_authorization_ref (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, auth);
        auth->refcount++;
        return auth;
}

/**
 * polkit_authorization_unref:
 * @auth: the authorization object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 *
 * Since: 0.7
 **/
void
polkit_authorization_unref (PolKitAuthorization *auth)
{
        g_return_if_fail (auth != NULL);
        auth->refcount--;
        if (auth->refcount > 0) 
                return;

        g_free (auth->entry_in_auth_file);
        g_free (auth->action_id);
        g_free (auth->session_id);
        if (auth->constraint != NULL)
                polkit_authorization_constraint_unref (auth->constraint);
        g_free (auth);
}

/**
 * polkit_authorization_debug:
 * @auth: the object
 * 
 * Print debug details
 *
 * Since: 0.7
 **/
void
polkit_authorization_debug (PolKitAuthorization *auth)
{
        g_return_if_fail (auth != NULL);
        _pk_debug ("PolKitAuthorization: refcount=%d", auth->refcount);
        _pk_debug (" scope          = %d",  auth->scope);
        _pk_debug (" pid            = %d",  auth->pid);
        _pk_debug (" pid_start_time = %Lu", auth->pid_start_time);
        _pk_debug (" action_id      = %s",  auth->action_id);
        _pk_debug (" when           = %Lu", (polkit_uint64_t) auth->when);
        _pk_debug (" auth_as_uid    = %d",  auth->authenticated_as_uid);
}

/**
 * polkit_authorization_validate:
 * @auth: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 *
 * Since: 0.7
 **/
polkit_bool_t
polkit_authorization_validate (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, FALSE);

        return TRUE;
}

/**
 * polkit_authorization_get_action_id:
 * @auth: the object
 *
 * Get the action this authorization is for
 *
 * Returns: the action id. Caller should not free this string.
 *
 * Since: 0.7
 */ 
const char *
polkit_authorization_get_action_id (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, NULL);

        return auth->action_id;
}

/**
 * polkit_authorization_get_scope:
 * @auth: the object
 *
 * Get the scope of the authorization; e.g. whether it's confined to a
 * single process, a single session or can be retained
 * indefinitely. Also keep in mind that an authorization is subject to
 * constraints, see polkit_authorization_get_constraint() for details.
 *
 * Returns: the scope
 *
 * Since: 0.7
 */ 
PolKitAuthorizationScope
polkit_authorization_get_scope (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, 0);

        return auth->scope;
}

/**
 * polkit_authorization_scope_process_get_pid:
 * @auth: the object
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
polkit_authorization_scope_process_get_pid (PolKitAuthorization *auth, 
                                            pid_t *out_pid, 
                                            polkit_uint64_t *out_pid_start_time)
{
        g_return_val_if_fail (auth != NULL, FALSE);
        g_return_val_if_fail (out_pid != NULL, FALSE);
        g_return_val_if_fail (out_pid_start_time != NULL, FALSE);
        g_return_val_if_fail (auth->scope == POLKIT_AUTHORIZATION_SCOPE_PROCESS || 
                              auth->scope == POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT, FALSE);

        *out_pid = auth->pid;
        *out_pid_start_time = auth->pid_start_time;

        return TRUE;
}

/**
 * polkit_authorization_scope_session_get_ck_objref:
 * @auth: the object
 *
 * Gets the ConsoleKit object path for the session the authorization
 * is confined to.
 *
 * Returns: #NULL if scope wasn't session
 *
 * Since: 0.7
 */ 
const char *
polkit_authorization_scope_session_get_ck_objref (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, FALSE);
        g_return_val_if_fail (auth->scope == POLKIT_AUTHORIZATION_SCOPE_SESSION, FALSE);

        return auth->session_id;
}

/**
 * polkit_authorization_get_uid:
 * @auth: the object
 *
 * Gets the UNIX user id for the user the authorization is confined
 * to.
 *
 * Returns: The UNIX user id for whom the authorization is confied to
 *
 * Since: 0.7
 */ 
uid_t
polkit_authorization_get_uid (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, 0);
        return auth->uid;
}

/**
 * polkit_authorization_get_time_of_grant:
 * @auth: the object
 *
 * Returns the point in time the authorization was granted. The value
 * is UNIX time, e.g. number of seconds since the Epoch Jan 1, 1970
 * 0:00 UTC.
 *
 * Returns: When authorization was granted
 *
 * Since: 0.7
 */ 
time_t
polkit_authorization_get_time_of_grant (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, 0);
        return auth->when;
}

/**
 * polkit_authorization_was_granted_via_defaults:
 * @auth: the object
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
polkit_authorization_was_granted_via_defaults (PolKitAuthorization *auth,
                                               uid_t *out_user_authenticated_as)
{
        g_return_val_if_fail (auth != NULL, FALSE);
        g_return_val_if_fail (out_user_authenticated_as != NULL, FALSE);

        if (auth->explicitly_granted)
                return FALSE;

        *out_user_authenticated_as = auth->authenticated_as_uid;
        return TRUE;
}

/**
 * polkit_authorization_was_granted_explicitly:
 * @auth: the object
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
polkit_authorization_was_granted_explicitly (PolKitAuthorization *auth,
                                             uid_t *out_by_whom)
{
        g_return_val_if_fail (auth != NULL, FALSE);
        g_return_val_if_fail (out_by_whom != NULL, FALSE);

        if (!auth->explicitly_granted)
                return FALSE;

        *out_by_whom = auth->explicitly_granted_by;

        return TRUE;
}

/**
 * polkit_authorization_get_constraint:
 * @auth: the object
 *
 * Get the constraint associated with an authorization.
 *
 * Returns: The constraint. Caller shall not unref this object.
 *
 * Since: 0.7
 */ 
PolKitAuthorizationConstraint *
polkit_authorization_get_constraint (PolKitAuthorization *auth)
{
        g_return_val_if_fail (auth != NULL, FALSE);
        return auth->constraint;
}

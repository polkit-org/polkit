/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-db.c : Represents the authorization database
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
#include "polkit-authorization-db.h"
#include "polkit-utils.h"

/* For now, redirect to the old stuff */
#include "polkit-grant-database.h"

/**
 * SECTION:polkit-authorization-db
 * @title: Authorization Database
 * @short_description: An interface to the database storing authorizations
 *
 * This class is used to represent entries in the authorization
 * database. TODO: needs to be pluggable
 *
 * Since: 0.7
 **/

/**
 * PolKitAuthorizationDB:
 *
 * Objects of this class are used to represent entries in the
 * authorization database.
 *
 * Since: 0.7
 **/
struct _PolKitAuthorizationDB
{
        int refcount;
};

/**
 * polkit_authorization_db_new:
 * 
 * Create a new #PolKitAuthorizationDB object.
 * 
 * Returns: the new object
 *
 * Since: 0.7
 **/
PolKitAuthorizationDB *
polkit_authorization_db_new (void)
{
        PolKitAuthorizationDB *authdb;
        authdb = g_new0 (PolKitAuthorizationDB, 1);
        authdb->refcount = 1;
        return authdb;
}

/**
 * polkit_authorization_db_ref:
 * @authdb: the object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 *
 * Since: 0.7
 **/
PolKitAuthorizationDB *
polkit_authorization_db_ref (PolKitAuthorizationDB *authdb)
{
        g_return_val_if_fail (authdb != NULL, authdb);
        authdb->refcount++;
        return authdb;
}

/**
 * polkit_authorization_db_unref:
 * @authdb: the object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 *
 * Since: 0.7
 **/
void
polkit_authorization_db_unref (PolKitAuthorizationDB *authdb)
{
        g_return_if_fail (authdb != NULL);
        authdb->refcount--;
        if (authdb->refcount > 0) 
                return;
        g_free (authdb);
}

/**
 * polkit_authorization_db_debug:
 * @authdb: the object
 * 
 * Print debug details
 *
 * Since: 0.7
 **/
void
polkit_authorization_db_debug (PolKitAuthorizationDB *authdb)
{
        g_return_if_fail (authdb != NULL);
        _pk_debug ("PolKitAuthorizationDB: refcount=%d", authdb->refcount);
}

/**
 * polkit_authorization_db_validate:
 * @authdb: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 *
 * Since: 0.7
 **/
polkit_bool_t
polkit_authorization_db_validate (PolKitAuthorizationDB *authdb)
{
        g_return_val_if_fail (authdb != NULL, FALSE);

        return TRUE;
}


/**
 * polkit_authorization_db_is_session_authorized:
 * @authdb: the authorization database
 * @action: the action to check for
 * @session: the session to check for
 * @out_is_authorized: return location
 *
 * Looks in the authorization database and determine if a processes
 * from the given session are authorized to do the given specific
 * action.
 *
 * Returns: #TRUE if the look up was performed; #FALSE if the caller
 * of this function lacks privileges to ask this question (e.g. asking
 * about a user that is not himself).
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_is_session_authorized (PolKitAuthorizationDB *authdb,
                                               PolKitAction          *action,
                                               PolKitSession         *session,
                                               polkit_bool_t         *out_is_authorized)
{
        return FALSE;
}

/**
 * polkit_authorization_db_is_caller_authorized:
 * @authdb: the authorization database
 * @action: the action to check for
 * @caller: the caller to check for
 * @out_is_authorized: return location
 *
 * Looks in the authorization database if the given caller is
 * authorized to do the given action.
 *
 * Returns: #TRUE if the look up was performed; #FALSE if the caller
 * of this function lacks privileges to ask this question (e.g. asking
 * about a user that is not himself).
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_is_caller_authorized (PolKitAuthorizationDB *authdb,
                                              PolKitAction          *action,
                                              PolKitCaller          *caller,
                                              polkit_bool_t         *out_is_authorized)
{
        g_return_val_if_fail (out_is_authorized != NULL, FALSE);
        *out_is_authorized = _polkit_grantdb_check_can_caller_do_action (action, caller);
        return TRUE;
}


/**
 * polkit_authorization_db_add_entry_process:
 * @authdb: the authorization database
 * @action: the action
 * @caller: the caller
 * @how: the value from "defaults" section of the
 * <literal>.policy</literal> file
 * @user_authenticated_as: the user that was authenticated
 *
 * Write an entry to the authorization database to indicate that the
 * given caller is authorized for the given action.
 *
 * Note that this function should only be used by
 * <literal>libpolkit-grant</literal> or other sufficiently privileged
 * processes that deals with managing authorizations. It should never
 * be used by mechanisms or applications.
 *
 * Returns: #TRUE if an entry was written to the authorization
 * database, #FALSE if the caller of this function is not sufficiently
 * privileged.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_add_entry_process          (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    PolKitCaller          *caller,
                                                    PolKitResult           how,
                                                    uid_t                  user_authenticated_as)
{
        char *action_id;
        pid_t caller_pid;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (caller != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &action_id))
                return FALSE;

        if (!polkit_caller_get_pid (caller, &caller_pid))
                return FALSE;

        return _polkit_grantdb_write_pid (action_id, caller_pid);;
}

/**
 * polkit_authorization_db_add_entry_session:
 * @authdb: the authorization database
 * @action: the action
 * @session: the session
 * @how: the value from "defaults" section of the
 * <literal>.policy</literal> file
 * @user_authenticated_as: the user that was authenticated
 *
 * Write an entry to the authorization database to indicate that the
 * given session is authorized for the given action.
 *
 * Note that this function should only be used by
 * <literal>libpolkit-grant</literal> or other sufficiently privileged
 * processes that deals with managing authorizations. It should never
 * be used by mechanisms or applications.
 *
 * Returns: #TRUE if an entry was written to the authorization
 * database, #FALSE if the caller of this function is not sufficiently
 * privileged.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_add_entry_session          (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    PolKitSession         *session,
                                                    PolKitResult           how,
                                                    uid_t                  user_authenticated_as)
{
        char *action_id;
        char *session_objpath;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (session != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &action_id))
                return FALSE;

        if (!polkit_session_get_ck_objref (session, &session_objpath))
                return FALSE;

        return _polkit_grantdb_write_keep_session (action_id, session_objpath);;
}

/**
 * polkit_authorization_db_add_entry_always:
 * @authdb: the authorization database
 * @action: the action
 * @uid: the user
 * @how: the value from "defaults" section of the
 * <literal>.policy</literal> file
 * @user_authenticated_as: the user that was authenticated
 *
 * Write an entry to the authorization database to indicate that the
 * given user is authorized for the given action.
 *
 * Note that this function should only be used by
 * <literal>libpolkit-grant</literal> or other sufficiently privileged
 * processes that deals with managing authorizations. It should never
 * be used by mechanisms or applications.
 *
 * Returns: #TRUE if an entry was written to the authorization
 * database, #FALSE if the caller of this function is not sufficiently
 * privileged.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_add_entry_always           (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    uid_t                  uid,
                                                    PolKitResult           how,
                                                    uid_t                  user_authenticated_as)
{
        char *action_id;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &action_id))
                return FALSE;

        return _polkit_grantdb_write_keep_always (action_id, uid);
}

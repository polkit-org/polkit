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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#include <glib.h>

#include "polkit-debug.h"
#include "polkit-authorization-db.h"
#include "polkit-utils.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-authorization-db
 * @title: Authorization Database
 * @short_description: Reading from and writing to the database storing authorizations
 *
 * This class presents an abstraction of the authorization database as
 * well as methods for reading and writing to it.
 *
 * The reading parts are in <literal>libpolkit</literal> and the
 * writing parts are in <literal>libpolkit-grant</literal>.
 *
 * Since: 0.7
 **/

/**
 * PolKitAuthorizationDB:
 *
 * Objects of this class are used to represent the authorization
 * database.
 *
 * Since: 0.7
 **/
struct _PolKitAuthorizationDB;

/* PolKitAuthorizationDB structure is defined in polkit/polkit-private.h */

static void
_free_authlist (GSList *authlist)
{
        if (authlist != NULL) {
                g_slist_foreach (authlist, (GFunc) polkit_authorization_unref, NULL);
                g_slist_free (authlist);
        }
}


/**
 * polkit_authorization_db_get_capabilities:
 *
 * Determine what capabilities the authorization backend has.
 *
 * Returns: Flags from the #PolKitAuthorizationDBCapability enumeration
 *
 * Since: 0.7
 */
PolKitAuthorizationDBCapability
polkit_authorization_db_get_capabilities (void)
{
        return POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN;
}

/**
 * _polkit_authorization_db_new:
 * 
 * Create a new #PolKitAuthorizationDB object.
 * 
 * Returns: the new object
 *
 * Since: 0.7
 **/
PolKitAuthorizationDB *
_polkit_authorization_db_new (void)
{
        PolKitAuthorizationDB *authdb;

        authdb = g_new0 (PolKitAuthorizationDB, 1);
        authdb->refcount = 1;

        /* set up the hashtable */
        _polkit_authorization_db_invalidate_cache (authdb);
        return authdb;
}

void
_polkit_authorization_db_pfe_foreach   (PolKitPolicyCache *policy_cache, 
                                        PolKitPolicyCacheForeachFunc callback,
                                        void *user_data)
{
}

PolKitPolicyFileEntry* 
_polkit_authorization_db_pfe_get_by_id (PolKitPolicyCache *policy_cache, 
                                        const char *action_id)
{
        return NULL;
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
        g_hash_table_destroy (authdb->uid_to_authlist);
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
 * _polkit_authorization_db_invalidate_cache:
 * @authdb: authorization database
 *
 * Tell the authorization database to invalidate any caches it might
 * employ. This is called by #PolKitContext whenever configuration or
 * anything else changes.
 *
 * Since: 0.7
 */
void
_polkit_authorization_db_invalidate_cache (PolKitAuthorizationDB *authdb)
{
        /* out with the old, in the with new */
        if (authdb->uid_to_authlist != NULL) {
                g_hash_table_destroy (authdb->uid_to_authlist);
        }
        authdb->uid_to_authlist = g_hash_table_new_full (g_direct_hash,
                                                         g_direct_equal,
                                                         NULL,
                                                         (GDestroyNotify) _free_authlist);
}

/**
 * _authdb_get_auths_for_uid:
 * @authdb: authorization database
 * @uid: uid to get authorizations for. If -1 is passed authorizations
 * for all users will be returned.
 * @error: return location for error
 *
 * Internal function to get authorizations for a uid.
 *
 * Returns: A singly-linked list of #PolKitAuthorization
 * objects. Caller shall not free this list. Returns #NULL if either
 * calling process is not sufficiently privileged (error will be set)
 * or if there are no authorizations for the given uid.
 *
 * Since: 0.7
 */
static GSList *
_authdb_get_auths_for_uid (PolKitAuthorizationDB *authdb,
                           uid_t                  uid,
                           PolKitError          **error)
{
        GSList *ret;
        char *helper_argv[] = {PACKAGE_LIBEXEC_DIR "/polkit-read-auth-helper", NULL, NULL};
        gint exit_status;
        GError *g_error;
        char *standard_output;
        size_t len;
        off_t n;

        ret = NULL;
        standard_output = NULL;

        /* first, see if this is in the cache */
        ret = g_hash_table_lookup (authdb->uid_to_authlist, (gpointer) uid);
        if (ret != NULL)
                goto out;

        helper_argv[1] = g_strdup_printf ("%d", uid);

        /* we need to do this through a setgid polkituser helper
         * because the auth file is readable only for uid 0 and gid
         * polkituser.
         */
        g_error = NULL;
        if (!g_spawn_sync (NULL,             /* const gchar *working_directory */
                           helper_argv,      /* gchar **argv */
                           NULL,             /* gchar **envp */
                           0,                /* GSpawnFlags flags */
                           NULL,             /* GSpawnChildSetupFunc child_setup */
                           NULL,             /* gpointer user_data */
                           &standard_output, /* gchar **standard_output */
                           NULL,             /* gchar **standard_error */
                           &exit_status,     /* gint *exit_status */
                           &g_error)) {      /* GError **error */
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Error spawning read auth helper: %s",
                                        g_error->message);
                g_error_free (g_error);
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                g_warning ("Read auth helper crashed!");
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Read auth helper crashed!");
                goto out;
        } else if (WEXITSTATUS(exit_status) != 0) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS, 
                                        uid > 0 ?
                                        "uid %d is not authorized to read authorizations for uid %d (requires org.freedesktop.policykit.read)" : 
                                        "uid %d is not authorized to read all authorizations (requires org.freedesktop.policykit.read)",
                                        getuid (), uid);
                goto out;
        }

        len = strlen (standard_output);

        /* parse one line at a time (modifies standard_output in place) */
        n = 0;
        while (n < len) {
                off_t m;
                char *line;
                PolKitAuthorization *auth;

                m = n;
                while (m < len && standard_output[m] != '\0') {
                        if (standard_output[m] == '\n')
                                break;
                        m++;
                }
                /* check EOF */
                if (standard_output[m] == '\0')
                        break;
                standard_output[m] = '\0';

                line = standard_output + n;

                if (strlen (line) >= 2 && strncmp (line, "#uid=", 5) == 0) {
                        uid = (uid_t) atoi (line + 5);
                }

                if (strlen (line) >= 2 && line[0] != '#') {
                        auth = _polkit_authorization_new_for_uid (line, uid);
                        
                        if (auth != NULL) {
                                ret = g_slist_prepend (ret, auth);
                        }
                }

                n = m + 1;
        }

        g_hash_table_insert (authdb->uid_to_authlist, (gpointer) uid, ret);

out:
        g_free (helper_argv[1]);
        g_free (standard_output);
        return ret;
}


static polkit_bool_t 
_internal_foreach (PolKitAuthorizationDB       *authdb,
                   PolKitAction                *action,
                   uid_t                        uid,
                   PolKitAuthorizationDBForeach cb,
                   void                        *user_data,
                   PolKitError                **error)
{
        GSList *l;
        GSList *auths;
        polkit_bool_t ret;
        char *action_id;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (cb != NULL, FALSE);

        ret = FALSE;

        if (action == NULL) {
                action_id = NULL;
        } else {
                if (!polkit_action_get_action_id (action, &action_id))
                        goto out;
        }

        auths = _authdb_get_auths_for_uid (authdb, uid, error);
        if (auths == NULL)
                goto out;

        for (l = auths; l != NULL; l = l->next) {
                PolKitAuthorization *auth = l->data;

                if (action_id != NULL) {
                        if (strcmp (polkit_authorization_get_action_id (auth), action_id) != 0) {
                                continue;
                        }
                }

                if (cb (authdb, auth, user_data)) {
                        ret = TRUE;
                        goto out;
                }
        }

out:
        return ret;
}


/**
 * polkit_authorization_db_foreach:
 * @authdb: authorization database
 * @cb: callback
 * @user_data: user data to pass to callback
 * @error: return location for error
 *
 * Iterate over all entries in the authorization database.
 *
 * Note that unless the calling process has the authorization
 * org.freedesktop.policykit.read this function may return an error.
 *
 * Returns: #TRUE if the callback returned #TRUE to stop iterating. If
 * #FALSE, either error may be set or the callback returns #FALSE on
 * every invocation.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_foreach (PolKitAuthorizationDB       *authdb,
                                 PolKitAuthorizationDBForeach cb,
                                 void                        *user_data,
                                 PolKitError                **error)
{
        return _internal_foreach (authdb, NULL, -1, cb, user_data, error);
}

/**
 * polkit_authorization_db_foreach_for_uid:
 * @authdb: authorization database
 * @uid: user to get authorizations for
 * @cb: callback
 * @user_data: user data to pass to callback
 * @error: return location for error
 *
 * Iterate over all entries in the authorization database for a given
 * user.
 *
 * Note that if the calling process asks for authorizations for a
 * different uid than itself and it lacks the authorization
 * org.freedesktop.policykit.read this function may return an error.
 *
 * Returns: #TRUE if the callback returned #TRUE to stop iterating. If
 * #FALSE, either error may be set or the callback returns #FALSE on
 * every invocation.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_foreach_for_uid (PolKitAuthorizationDB       *authdb,
                                         uid_t                        uid,
                                         PolKitAuthorizationDBForeach cb,
                                         void                        *user_data,
                                         PolKitError                **error)
{
        return _internal_foreach (authdb, NULL, uid, cb, user_data, error);
}

/**
 * polkit_authorization_db_foreach_for_action:
 * @authdb: authorization database
 * @action: action to get authorizations for
 * @cb: callback
 * @user_data: user data to pass to callback
 * @error: return location for error
 *
 * Iterate over all entries in the authorization database for a given
 * action.
 *
 * Note that unless the calling process has the authorization
 * org.freedesktop.policykit.read this function may return an error.
 *
 * Returns: #TRUE if the callback returned #TRUE to stop iterating. If
 * #FALSE, either error may be set or the callback returns #FALSE on
 * every invocation.
 *
 * Since: 0.7
 */
polkit_bool_t 
polkit_authorization_db_foreach_for_action (PolKitAuthorizationDB       *authdb,
                                            PolKitAction                *action,
                                            PolKitAuthorizationDBForeach cb,
                                            void                        *user_data,
                                            PolKitError                **error)
{
        g_return_val_if_fail (action != NULL, FALSE);
        return _internal_foreach (authdb, action, -1, cb, user_data, error);
}

/**
 * polkit_authorization_db_foreach_for_action_for_uid:
 * @authdb: authorization database
 * @action: action to get authorizations for
 * @uid: user to get authorizations for
 * @cb: callback
 * @user_data: user data to pass to callback
 * @error: return location for error
 *
 * Iterate over all entries in the authorization database for a given
 * action and user.
 *
 * Note that if the calling process asks for authorizations for a
 * different uid than itself and it lacks the authorization
 * org.freedesktop.policykit.read this function may return an error.
 *
 * Returns: #TRUE if the callback returned #TRUE to stop iterating. If
 * #FALSE, either error may be set or the callback returns #FALSE on
 * every invocation.
 *
 * Since: 0.7
 */
polkit_bool_t 
polkit_authorization_db_foreach_for_action_for_uid (PolKitAuthorizationDB       *authdb,
                                                    PolKitAction                *action,
                                                    uid_t                        uid,
                                                    PolKitAuthorizationDBForeach cb,
                                                    void                        *user_data,
                                                    PolKitError                **error)
{
        g_return_val_if_fail (action != NULL, FALSE);
        return _internal_foreach (authdb, action, uid, cb, user_data, error);
}


typedef struct {
        char *action_id;
        uid_t session_uid; 
        char *session_objpath;
        PolKitSession *session;
} CheckDataSession;

static polkit_bool_t 
_check_auth_for_session (PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{
        gboolean ret;
        CheckDataSession *cd = (CheckDataSession *) user_data;
        PolKitAuthorizationConstraint *constraint;

        ret = FALSE;

        if (strcmp (polkit_authorization_get_action_id (auth), cd->action_id) != 0)
                goto no_match;

        constraint = polkit_authorization_get_constraint (auth);
        if (!polkit_authorization_constraint_check_session (constraint, cd->session))
                goto no_match;

        switch (polkit_authorization_get_scope (auth))
        {
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS:
                goto no_match;

        case POLKIT_AUTHORIZATION_SCOPE_SESSION:
                if (strcmp (polkit_authorization_scope_session_get_ck_objref (auth), cd->session_objpath) != 0)
                        goto no_match;
                break;

        case POLKIT_AUTHORIZATION_SCOPE_ALWAYS:
                break;
        }

        ret = TRUE;

no_match:
        return ret;
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
        polkit_bool_t ret;
        CheckDataSession cd;

        ret = FALSE;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_is_authorized != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &cd.action_id))
                return FALSE;

        if (!polkit_session_get_uid (session, &cd.session_uid))
                return FALSE;

        cd.session = session;

        if (!polkit_session_get_ck_objref (session, &cd.session_objpath) || cd.session_objpath == NULL)
                return FALSE;

        ret = TRUE;

        *out_is_authorized = FALSE;
        if (polkit_authorization_db_foreach_for_uid (authdb,
                                                     cd.session_uid, 
                                                     _check_auth_for_session,
                                                     &cd,
                                                     NULL)) {
                *out_is_authorized = TRUE;
        }

        return ret;
}

typedef struct {
        char *action_id;
        uid_t caller_uid; 
        pid_t caller_pid;
        polkit_uint64_t caller_pid_start_time;
        char *session_objpath;
        PolKitCaller *caller;
} CheckData;

static polkit_bool_t 
_check_auth_for_caller (PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{
        gboolean ret;
        pid_t caller_pid;
        polkit_uint64_t caller_pid_start_time;
        CheckData *cd = (CheckData *) user_data;
        PolKitAuthorizationConstraint *constraint;

        ret = FALSE;

        if (strcmp (polkit_authorization_get_action_id (auth), cd->action_id) != 0)
                goto no_match;

        constraint = polkit_authorization_get_constraint (auth);
        if (!polkit_authorization_constraint_check_caller (constraint, cd->caller))
                goto no_match;

        switch (polkit_authorization_get_scope (auth))
        {
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS:
                if (!polkit_authorization_scope_process_get_pid (auth, &caller_pid, &caller_pid_start_time))
                        goto no_match;
                if (!(caller_pid == cd->caller_pid && caller_pid_start_time == cd->caller_pid_start_time))
                        goto no_match;
                break;

        case POLKIT_AUTHORIZATION_SCOPE_SESSION:
                if (cd->session_objpath == NULL)
                        goto no_match;
                if (strcmp (polkit_authorization_scope_session_get_ck_objref (auth), cd->session_objpath) != 0)
                        goto no_match;
                break;

        case POLKIT_AUTHORIZATION_SCOPE_ALWAYS:
                break;
        }

        ret = TRUE;

no_match:
        return ret;
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
        PolKitSession *session;
        polkit_bool_t ret;
        CheckData cd;

        ret = FALSE;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_is_authorized != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &cd.action_id))
                return FALSE;

        if (!polkit_caller_get_pid (caller, &cd.caller_pid))
                return FALSE;

        if (!polkit_caller_get_uid (caller, &cd.caller_uid))
                return FALSE;

        cd.caller = caller;

        cd.caller_pid_start_time = polkit_sysdeps_get_start_time_for_pid (cd.caller_pid);
        if (cd.caller_pid_start_time == 0)
                return FALSE;

        /* Caller does not _have_ to be member of a session */
        cd.session_objpath = NULL;
        if (polkit_caller_get_ck_session (caller, &session) && session != NULL) {
                if (!polkit_session_get_ck_objref (session, &cd.session_objpath))
                        cd.session_objpath = NULL;
        }

        ret = TRUE;

        *out_is_authorized = FALSE;
        if (polkit_authorization_db_foreach_for_uid (authdb,
                                                     cd.caller_uid, 
                                                     _check_auth_for_caller,
                                                     &cd,
                                                     NULL)) {
                *out_is_authorized = TRUE;
        }

        return ret;
}

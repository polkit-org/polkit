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
#include "polkit-test.h"
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

polkit_bool_t
_polkit_authorization_db_pfe_foreach   (PolKitPolicyCache *policy_cache, 
                                        PolKitPolicyCacheForeachFunc callback,
                                        void *user_data)
{
        return FALSE;
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
        kit_return_val_if_fail (authdb != NULL, authdb);
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
        kit_return_if_fail (authdb != NULL);
        authdb->refcount--;
        if (authdb->refcount > 0) 
                return;
        kit_hash_unref (authdb->uid_to_authlist);
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
        kit_return_if_fail (authdb != NULL);
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
        kit_return_val_if_fail (authdb != NULL, FALSE);

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
                kit_hash_unref (authdb->uid_to_authlist);
        }
        authdb->uid_to_authlist = kit_hash_new (kit_hash_direct_hash_func,
                                                kit_hash_direct_equal_func,
                                                NULL,
                                                NULL,
                                                NULL,
                                                (KitFreeFunc) _free_authlist);
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
        ret = kit_hash_lookup (authdb->uid_to_authlist, (void *) uid, NULL);
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

        kit_hash_insert (authdb->uid_to_authlist, (void *) uid, ret);

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

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (cb != NULL, FALSE);

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
        kit_return_val_if_fail (action != NULL, FALSE);
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
        kit_return_val_if_fail (action != NULL, FALSE);
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
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT:
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
 * Looks in the authorization database and determine if processes from
 * the given session are authorized to do the given specific action.
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

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (action != NULL, FALSE);
        kit_return_val_if_fail (session != NULL, FALSE);
        kit_return_val_if_fail (out_is_authorized != NULL, FALSE);

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
        polkit_bool_t revoke_if_one_shot;
} CheckData;

static polkit_bool_t 
_check_auth_for_caller (PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{

        gboolean ret;
        pid_t caller_pid;
        polkit_uint64_t caller_pid_start_time;
        CheckData *cd = (CheckData *) user_data;
        PolKitAuthorizationConstraint *constraint;
        PolKitError *error;

        ret = FALSE;

        if (strcmp (polkit_authorization_get_action_id (auth), cd->action_id) != 0)
                goto no_match;

        constraint = polkit_authorization_get_constraint (auth);
        if (!polkit_authorization_constraint_check_caller (constraint, cd->caller))
                goto no_match;

        switch (polkit_authorization_get_scope (auth))
        {
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT:
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS:
                if (!polkit_authorization_scope_process_get_pid (auth, &caller_pid, &caller_pid_start_time))
                        goto no_match;
                if (!(caller_pid == cd->caller_pid && caller_pid_start_time == cd->caller_pid_start_time))
                        goto no_match;

                if (polkit_authorization_get_scope (auth) == POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT) {

                        /* it's a match already; revoke if asked to do so */
                        if (cd->revoke_if_one_shot) {
                                error = NULL;
                                if (!polkit_authorization_db_revoke_entry (authdb, auth, &error)) {
                                        g_warning ("Cannot revoke one-shot auth: %s: %s", 
                                                   polkit_error_get_error_name (error),
                                                   polkit_error_get_error_message (error));
                                        polkit_error_free (error);
                                }
                        }
                }
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
 * @revoke_if_one_shot: Whether to revoke one-shot authorizations. See
 * discussion in polkit_context_is_caller_authorized() for details.
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
                                              polkit_bool_t          revoke_if_one_shot,
                                              polkit_bool_t         *out_is_authorized)
{
        PolKitSession *session;
        polkit_bool_t ret;
        CheckData cd;

        ret = FALSE;

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (action != NULL, FALSE);
        kit_return_val_if_fail (caller != NULL, FALSE);
        kit_return_val_if_fail (out_is_authorized != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &cd.action_id))
                return FALSE;

        if (!polkit_caller_get_pid (caller, &cd.caller_pid))
                return FALSE;

        if (!polkit_caller_get_uid (caller, &cd.caller_uid))
                return FALSE;

        cd.caller = caller;
        cd.revoke_if_one_shot = revoke_if_one_shot;

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

/**
 * polkit_authorization_db_revoke_entry:
 * @authdb: the authorization database
 * @auth: the authorization to revoke
 * @error: return location for error
 *
 * Removes an authorization from the authorization database. This uses
 * a privileged helper /usr/libexec/polkit-revoke-helper.
 *
 * Returns: #TRUE if the authorization was revoked, #FALSE otherwise and error is set
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_revoke_entry (PolKitAuthorizationDB *authdb,
                                      PolKitAuthorization   *auth,
                                      PolKitError           **error)
{
        GError *g_error;
        char *helper_argv[] = {PACKAGE_LIBEXEC_DIR "/polkit-revoke-helper", "", NULL, NULL, NULL};
        const char *auth_file_entry;
        gboolean ret;
        gint exit_status;

        ret = FALSE;

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (auth != NULL, FALSE);

        auth_file_entry = _polkit_authorization_get_authfile_entry (auth);
        //g_debug ("should delete line '%s'", auth_file_entry);

        helper_argv[1] = (char *) auth_file_entry;
        helper_argv[2] = "uid";
        helper_argv[3] = g_strdup_printf ("%d", polkit_authorization_get_uid (auth));

        g_error = NULL;
        if (!g_spawn_sync (NULL,         /* const gchar *working_directory */
                           helper_argv,  /* gchar **argv */
                           NULL,         /* gchar **envp */
                           0,            /* GSpawnFlags flags */
                           NULL,         /* GSpawnChildSetupFunc child_setup */
                           NULL,         /* gpointer user_data */
                           NULL,         /* gchar **standard_output */
                           NULL,         /* gchar **standard_error */
                           &exit_status, /* gint *exit_status */
                           &g_error)) {  /* GError **error */
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Error spawning revoke helper: %s",
                                        g_error->message);
                g_error_free (g_error);
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                g_warning ("Revoke helper crashed!");
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Revoke helper crashed!");
                goto out;
        } else if (WEXITSTATUS(exit_status) != 0) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_NOT_AUTHORIZED_TO_REVOKE_AUTHORIZATIONS_FROM_OTHER_USERS, 
                                        "uid %d is not authorized to revoke authorizations from uid %d (requires org.freedesktop.policykit.revoke)",
                                        getuid (), polkit_authorization_get_uid (auth));
        } else {
                ret = TRUE;
        }
        
out:
        g_free (helper_argv[3]);
        return ret;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        PolKitAuthorizationDB *adb;
        const char test_passwd[] = 
                "pu1:x:50400:50400:PolKit Test user 1:/home/polkittest1:/bin/bash\n"
                "pu2:x:50401:50401:PolKit Test user 2:/home/polkittest2:/bin/bash\n";
        const char test_pu1_run[] =
                "";
        const char test_pu1_lib[] =
                "grant:org.freedesktop.policykit.read:1194634242:0:none\n";
        const char test_pu2_run[] =
                "";
        const char test_pu2_lib[] =
                "";
        
        if (setenv ("POLKIT_TEST_LOCALSTATE_DIR", TEST_DATA_DIR "authdb-test", 1) != 0)
                goto fail;

        if (setenv ("POLKIT_TEST_PASSWD_FILE", TEST_DATA_DIR "authdb-test/passwd", 1) != 0)
                goto fail;

        /* create test users */
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/passwd", 0644, 
                                    test_passwd, sizeof (test_passwd) - 1))
                goto out;

        /* seed the authdb with known defaults */
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/run/PolicyKit/user-pu1.auths", 0644, 
                                    test_pu1_run, sizeof (test_pu1_run) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/lib/PolicyKit/user-pu1.auths", 0644, 
                                    test_pu1_lib, sizeof (test_pu1_lib) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/run/PolicyKit/user-pu2.auths", 0644, 
                                    test_pu2_run, sizeof (test_pu2_run) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/lib/PolicyKit/user-pu2.auths", 0644, 
                                    test_pu2_lib, sizeof (test_pu2_lib) - 1))
                goto out;

        if ((adb = _polkit_authorization_db_new ()) == NULL)
                goto out;

        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50400", 1) != 0)
                goto fail;

        /* TODO: FIXME: this code is not finished */


        polkit_authorization_db_unref (adb);

out:
        if (unsetenv ("POLKIT_TEST_PRETEND_TO_BE_UID") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_LOCALSTATE_DIR") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_PASSWD_FILE") != 0)
                goto fail;

        return TRUE;
fail:
        return FALSE;
}


PolKitTest _test_authorization_db = {
        "polkit_authorization_db",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-db.c : Represents the authorization database
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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

static kit_bool_t
clear_auth (void *data, void *user_data, KitList *list)
{
        PolKitAuthorization *auth = (PolKitAuthorization *) data;
        polkit_authorization_unref (auth);
        return FALSE;
}

static void
_free_authlist (KitList *authlist)
{
        if (authlist != NULL) {
                kit_list_foreach (authlist, clear_auth, NULL);
                kit_list_free (authlist);
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

        authdb = kit_new0 (PolKitAuthorizationDB, 1);
        if (authdb == NULL)
                goto oom;
        authdb->refcount = 1;

        /* set up the hashtable */
        _polkit_authorization_db_invalidate_cache (authdb);
oom:
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
        if (authdb->uid_to_authlist != NULL)
                kit_hash_unref (authdb->uid_to_authlist);
        kit_free (authdb);
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
        polkit_debug ("PolKitAuthorizationDB: refcount=%d", authdb->refcount);
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
                authdb->uid_to_authlist = NULL;
        }
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
static KitList *
_authdb_get_auths_for_uid (PolKitAuthorizationDB *authdb,
                           const uid_t            uid,
                           PolKitError          **error)
{
        KitList *ret;
        char *helper_argv[] = {NULL, NULL, NULL};
        int exit_status;
        char *standard_output;
        size_t len;
        off_t n;

        ret = NULL;
        standard_output = NULL;

#ifdef POLKIT_BUILD_TESTS
        char helper_buf[256];
        char *helper_bin_dir;
        if ((helper_bin_dir = getenv ("POLKIT_TEST_BUILD_DIR")) != NULL) {
                kit_assert ((size_t) snprintf (helper_buf, sizeof (helper_buf), "%s/src/polkit/polkit-read-auth-helper-1", helper_bin_dir) < sizeof (helper_buf));
                helper_argv[0] = helper_buf;
        } else {
                helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-read-auth-helper-1";
        }
#else
        helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-read-auth-helper-1";
#endif

        /* first, see if this is in the cache */
        if (authdb->uid_to_authlist != NULL) {
                ret = kit_hash_lookup (authdb->uid_to_authlist, (void *) uid, NULL);
                if (ret != NULL)
                        goto out;
        }

        helper_argv[1] = kit_strdup_printf ("%d", uid);
        if (helper_argv[1] == NULL) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_OUT_OF_MEMORY, 
                                        "No memory");
                goto out;
        }

        /* we need to do this through a setgid polkituser helper
         * because the auth file is readable only for uid 0 and gid
         * polkituser.
         */
        if (!kit_spawn_sync (NULL,             /* const char  *working_directory */
                             0,                /* flags */
                             helper_argv,      /* char       **argv */
                             NULL,             /* char       **envp */
                             NULL,             /* char        *stdin */
                             &standard_output, /* char       **stdout */
                             NULL,             /* char       **stderr */
                             &exit_status)) {  /* int         *exit_status */
                if (errno == ENOMEM) {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_OUT_OF_MEMORY, 
                                                "Error spawning read auth helper: OOM");
                } else {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_GENERAL_ERROR, 
                                                "Error spawning read auth helper: %m");
                }
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                kit_warning ("Read auth helper crashed!");
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

        //kit_warning ("standard_output='%s'", standard_output);

        if (standard_output != NULL) {
                uid_t uid2;
                len = strlen (standard_output);

                uid2 = uid;
                
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
                                uid2 = (uid_t) atoi (line + 5);
                        }
                        
                        if (strlen (line) >= 2 && line[0] != '#') {
                                auth = _polkit_authorization_new_for_uid (line, uid2);
                                if (auth == NULL) {
                                        if (errno == ENOMEM) {
                                                polkit_error_set_error (error, 
                                                                        POLKIT_ERROR_OUT_OF_MEMORY, 
                                                                        "No memory");
                                                _free_authlist (ret);
                                                ret = NULL;
                                                goto out;
                                        } else {
                                                kit_warning ("Skipping invalid authline '%s'", line);
                                        }
                                }

                                //kit_warning (" #got %s", line);

                                if (auth != NULL) {
                                        KitList *ret2;
                                        /* we need the authorizations in the chronological order... 
                                         * (TODO: optimized: prepend, then reverse after all items have been inserted)
                                         */
                                        ret2 = kit_list_append (ret, auth);
                                        if (ret2 == NULL) {
                                                polkit_error_set_error (error, 
                                                                        POLKIT_ERROR_OUT_OF_MEMORY, 
                                                                        "No memory");
                                                polkit_authorization_unref (auth);
                                                _free_authlist (ret);
                                                ret = NULL;
                                                goto out;
                                        }
                                        ret = ret2;
                                }
                        }
                        
                        n = m + 1;
                }
        }

        if (authdb->uid_to_authlist == NULL) {
                authdb->uid_to_authlist = kit_hash_new (kit_hash_direct_hash_func,
                                                        kit_hash_direct_equal_func,
                                                        NULL,
                                                        NULL,
                                                        NULL,
                                                        (KitFreeFunc) _free_authlist);
        }

        if (authdb->uid_to_authlist == NULL || 
            !kit_hash_insert (authdb->uid_to_authlist, (void *) uid, ret)) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_OUT_OF_MEMORY, 
                                        "No memory");
                _free_authlist (ret);
                ret = NULL;
                goto out;
        }

out:
        kit_free (helper_argv[1]);
        kit_free (standard_output);
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
        KitList *l;
        KitList *auths;
        KitList *auths_copy;
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

        /* have to copy the list and ref the auths because the authdb
         * may disappear from under us due to revoke_if_one_shot...
         */
        auths_copy = kit_list_copy (auths);
        if (auths_copy == NULL) {
                polkit_error_set_error (error,
                                        POLKIT_ERROR_OUT_OF_MEMORY,
                                        "No memory");
                goto out;
        }
        for (l = auths_copy; l != NULL; l = l->next)
                polkit_authorization_ref ((PolKitAuthorization *) l->data);

        for (l = auths_copy; l != NULL; l = l->next) {
                PolKitAuthorization *auth = l->data;

                //kit_warning ("%d: action_id=%s uid=%d", 
                //             uid,
                //             polkit_authorization_get_action_id (auth),
                //             polkit_authorization_get_uid (auth));

                if (action_id != NULL) {
                        if (strcmp (polkit_authorization_get_action_id (auth), action_id) != 0) {
                                continue;
                        }
                }

                if (cb (authdb, auth, user_data)) {
                        ret = TRUE;
                        break;
                }
        }

        for (l = auths_copy; l != NULL; l = l->next)
                polkit_authorization_unref ((PolKitAuthorization *) l->data);
        kit_list_free (auths_copy);

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

        polkit_bool_t *out_is_authorized;
        polkit_bool_t *out_is_negative_authorized;
} CheckDataSession;

static polkit_bool_t 
_check_constraint_session (PolKitAuthorization *auth, PolKitAuthorizationConstraint *authc, void *user_data)
{
        PolKitSession *session = (PolKitSession *) user_data;

        if (!polkit_authorization_constraint_check_session (authc, session))
                goto no_match;

        return FALSE;
no_match:
        return TRUE;
}

static polkit_bool_t 
_check_auth_for_session (PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{
        polkit_bool_t ret;
        uid_t pimp_uid;
        polkit_bool_t is_negative;
        CheckDataSession *cd = (CheckDataSession *) user_data;

        ret = FALSE;

        if (strcmp (polkit_authorization_get_action_id (auth), cd->action_id) != 0)
                goto no_match;

        if (polkit_authorization_constraints_foreach (auth, _check_constraint_session, cd->session))
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

        if (!polkit_authorization_was_granted_explicitly (auth, &pimp_uid, &is_negative))
                is_negative = FALSE;

        if (is_negative) {
                *(cd->out_is_authorized) = FALSE;
                *(cd->out_is_negative_authorized) = TRUE;
        } else {
                *(cd->out_is_authorized) = TRUE;
                *(cd->out_is_negative_authorized) = FALSE;
        }

        /* keep iterating; we may find negative auths... */

        if (is_negative) {
                *(cd->out_is_authorized) = FALSE;
                *(cd->out_is_negative_authorized) = TRUE;
                /* it only takes a single negative auth to block things so stop iterating */
                ret = TRUE;
        } else {
                *(cd->out_is_authorized) = TRUE;
                *(cd->out_is_negative_authorized) = FALSE;
                /* keep iterating; we may find negative auths... */
        }

no_match:
        return ret;
}

/**
 * polkit_authorization_db_is_session_authorized:
 * @authdb: the authorization database
 * @action: the action to check for
 * @session: the session to check for
 * @out_is_authorized: return location
 * @out_is_negative_authorized: return location
 * @error: return location for error
 *
 * Looks in the authorization database and determine if processes from
 * the given session are authorized to do the given specific
 * action. If there is an authorization record that matches the
 * session, @out_is_authorized will be set to %TRUE. If there is a
 * negative authorization record matching the session
 * @out_is_negative_authorized will be set to %TRUE.
 *
 * Returns: #TRUE if the look up was performed; #FALSE if the caller
 * of this function lacks privileges to ask this question (e.g. asking
 * about a user that is not himself) or OOM (and @error will be set)
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_is_session_authorized (PolKitAuthorizationDB *authdb,
                                               PolKitAction          *action,
                                               PolKitSession         *session,
                                               polkit_bool_t         *out_is_authorized,
                                               polkit_bool_t         *out_is_negative_authorized,
                                               PolKitError          **error)
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

        cd.out_is_authorized = out_is_authorized;
        cd.out_is_negative_authorized = out_is_negative_authorized;
        *out_is_authorized = FALSE;
        *out_is_negative_authorized = FALSE;

        if (polkit_authorization_db_foreach_for_uid (authdb,
                                                     cd.session_uid, 
                                                     _check_auth_for_session,
                                                     &cd,
                                                     NULL)) {
                ;
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

        polkit_bool_t *out_is_authorized;
        polkit_bool_t *out_is_negative_authorized;

        PolKitError *error;
} CheckData;

static polkit_bool_t 
_check_constraint_caller (PolKitAuthorization *auth, PolKitAuthorizationConstraint *authc, void *user_data)
{
        PolKitCaller *caller = (PolKitCaller *) user_data;

        if (!polkit_authorization_constraint_check_caller (authc, caller))
                goto no_match;

        return FALSE;
no_match:
        return TRUE;
}

static polkit_bool_t 
_check_auth_for_caller (PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{
        polkit_bool_t ret;
        uid_t pimp_uid;
        polkit_bool_t is_negative;
        pid_t caller_pid;
        polkit_uint64_t caller_pid_start_time;
        CheckData *cd = (CheckData *) user_data;

        ret = FALSE;

        if (strcmp (polkit_authorization_get_action_id (auth), cd->action_id) != 0)
                goto no_match;

        if (polkit_authorization_constraints_foreach (auth, _check_constraint_caller, cd->caller))
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
                                cd->error = NULL;
                                if (!polkit_authorization_db_revoke_entry (authdb, auth, &(cd->error))) {
                                        //kit_warning ("Cannot revoke one-shot auth: %s: %s",
                                        //           polkit_error_get_error_name (cd->error),
                                        //           polkit_error_get_error_message (cd->error));
                                        /* stop iterating */
                                        ret = TRUE;
                                        goto no_match;
                                }
                                /* revoked; now purge internal cache */
                                _polkit_authorization_db_invalidate_cache (authdb);
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

        if (!polkit_authorization_was_granted_explicitly (auth, &pimp_uid, &is_negative))
                is_negative = FALSE;

        if (is_negative) {
                *(cd->out_is_authorized) = FALSE;
                *(cd->out_is_negative_authorized) = TRUE;
                /* it only takes a single negative auth to block things so stop iterating */
                ret = TRUE;
        } else {
                *(cd->out_is_authorized) = TRUE;
                *(cd->out_is_negative_authorized) = FALSE;
                /* keep iterating; we may find negative auths... */
        }


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
 * @out_is_negative_authorized: return location
 * @error: return location for error
 *
 * Looks in the authorization database if the given caller is
 * authorized to do the given action. If there is an authorization
 * record that matches the caller, @out_is_authorized will be set to
 * %TRUE. If there is a negative authorization record matching the
 * caller @out_is_negative_authorized will be set to %TRUE.
 *
 * Returns: #TRUE if the look up was performed; #FALSE if the caller
 * of this function lacks privileges to ask this question (e.g. asking
 * about a user that is not himself) or if OOM (and @error will be set)
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_is_caller_authorized (PolKitAuthorizationDB *authdb,
                                              PolKitAction          *action,
                                              PolKitCaller          *caller,
                                              polkit_bool_t          revoke_if_one_shot,
                                              polkit_bool_t         *out_is_authorized,
                                              polkit_bool_t         *out_is_negative_authorized,
                                              PolKitError          **error)
{
        PolKitSession *session;
        polkit_bool_t ret;
        CheckData cd;
        PolKitError *error2;

        ret = FALSE;

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (action != NULL, FALSE);
        kit_return_val_if_fail (caller != NULL, FALSE);
        kit_return_val_if_fail (out_is_authorized != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &cd.action_id))
                goto out;

        if (!polkit_caller_get_pid (caller, &cd.caller_pid))
                goto out;

        if (!polkit_caller_get_uid (caller, &cd.caller_uid))
                goto out;

        cd.caller = caller;
        cd.revoke_if_one_shot = revoke_if_one_shot;
        cd.error = NULL;

        cd.caller_pid_start_time = polkit_sysdeps_get_start_time_for_pid (cd.caller_pid);
        if (cd.caller_pid_start_time == 0) {
                if (errno == ENOMEM) {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_OUT_OF_MEMORY, 
                                                "No memory");
                } else {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_GENERAL_ERROR, 
                                                "Errno %d: %m", errno);
                }
                goto out;
        }

        /* Caller does not _have_ to be member of a session */
        cd.session_objpath = NULL;
        if (polkit_caller_get_ck_session (caller, &session) && session != NULL) {
                if (!polkit_session_get_ck_objref (session, &cd.session_objpath))
                        cd.session_objpath = NULL;
        }

        cd.out_is_authorized = out_is_authorized;
        cd.out_is_negative_authorized = out_is_negative_authorized;
        *out_is_authorized = FALSE;
        *out_is_negative_authorized = FALSE;

        error2 = NULL;
        if (polkit_authorization_db_foreach_for_uid (authdb,
                                                     cd.caller_uid, 
                                                     _check_auth_for_caller,
                                                     &cd,
                                                     &error2)) {
                ;
        }

        if (polkit_error_is_set (error2)) {
                if (error != NULL) {
                        *error = error2;
                } else {
                        polkit_error_free (error2);
                }
                goto out;
        }

        if (polkit_error_is_set (cd.error)) {
                if (error != NULL) {
                        *error = cd.error;
                } else {
                        polkit_error_free (cd.error);
                }
                goto out;
        }

        ret = TRUE;

out:
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
        char *helper_argv[] = {NULL, "", NULL, NULL, NULL};
        const char *auth_file_entry;
        polkit_bool_t ret;
        int exit_status;

        ret = FALSE;

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (auth != NULL, FALSE);

        auth_file_entry = _polkit_authorization_get_authfile_entry (auth);
        //g_debug ("should delete line '%s'", auth_file_entry);

#ifdef POLKIT_BUILD_TESTS
        char helper_buf[256];
        char *helper_bin_dir;
        if ((helper_bin_dir = getenv ("POLKIT_TEST_BUILD_DIR")) != NULL) {
                kit_assert ((size_t) snprintf (helper_buf, sizeof (helper_buf), "%s/src/polkit-grant/polkit-revoke-helper-1", helper_bin_dir) < sizeof (helper_buf));
                helper_argv[0] = helper_buf;
        } else {
                helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-revoke-helper-1";
        }
#else
        helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-revoke-helper-1";
#endif

        helper_argv[1] = (char *) auth_file_entry;
        helper_argv[2] = "uid";
        helper_argv[3] = kit_strdup_printf ("%d", polkit_authorization_get_uid (auth));
        if (helper_argv[3] == NULL) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_OUT_OF_MEMORY, 
                                        "Out of memory");
                goto out;
        }

        if (!kit_spawn_sync (NULL,             /* const char  *working_directory */
                             0,                /* flags */
                             helper_argv,      /* char       **argv */
                             NULL,             /* char       **envp */
                             NULL,             /* char        *stdin */
                             NULL,             /* char       **stdout */
                             NULL,             /* char       **stderr */
                             &exit_status)) {  /* int         *exit_status */
                if (errno == ENOMEM) {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_OUT_OF_MEMORY, 
                                                "Error spawning revoke helper: OOM");
                } else {
                        polkit_error_set_error (error, 
                                                POLKIT_ERROR_GENERAL_ERROR, 
                                                "Error spawning revoke helper: %m");
                }
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                kit_warning ("Revoke helper crashed!");
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
        kit_free (helper_argv[3]);
        return ret;
}

static polkit_bool_t
_check_self_block_foreach (PolKitAuthorizationDB *authdb,
                           PolKitAuthorization   *auth, 
                           void                  *user_data)
{
        polkit_bool_t *is_self_blocked = (polkit_bool_t *) user_data;
        polkit_bool_t is_negative;
        uid_t pimp_uid;
        polkit_bool_t ret;

        if (!polkit_authorization_was_granted_explicitly (auth, &pimp_uid, &is_negative))
                is_negative = FALSE;

        if (is_negative) {
                if (pimp_uid == getuid ()) {
                        *is_self_blocked = TRUE;
                        /* can't stop iterating.. there may be another one who blocked us too! */
                } else {
                        *is_self_blocked = FALSE;
                        ret = TRUE;
                        /* nope; someone else blocked us.. that's enough to ruin it */
                }                        
        }
        
        return ret;
}

/**
 * polkit_authorization_db_is_uid_blocked_by_self:
 * @authdb: the authorization database
 * @action: the action to check for
 * @uid: the user to check for
 * @error: return location for error
 *
 * Determine whether there exists negative authorizations for the
 * particular uid on the given action and whether those negative
 * authorization are "granted" by the uid itself.
 *
 * If uid is different from getuid(), e.g. if the calling process asks
 * for auths of another user this function will set an error if the
 * calling user is not authorized for org.freedesktop.policykit.read.
 *
 * Returns: Result of computation described above; if error is set
 * will return %FALSE.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_db_is_uid_blocked_by_self (PolKitAuthorizationDB *authdb,
                                                PolKitAction          *action,
                                                uid_t                  uid,
                                                PolKitError          **error)
{
        polkit_bool_t is_self_blocked;

        kit_return_val_if_fail (authdb != NULL, FALSE);
        kit_return_val_if_fail (action != NULL, FALSE);
                                
        is_self_blocked = FALSE;
        polkit_authorization_db_foreach_for_action_for_uid (authdb,
                                                            action,
                                                            uid,
                                                            _check_self_block_foreach,
                                                            &is_self_blocked,
                                                            error);

        return is_self_blocked;
}



#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        PolKitAuthorizationDB *adb;
        const char test_passwd[] = 
                "root:x:0:0:PolKit root user:/root:/bin/bash\n"
                POLKIT_USER ":x:50400:50400:PolKit user:/:/sbin/nologin\n"
                "pu1:x:50401:50401:PolKit Test user 0:/home/polkittest1:/bin/bash\n"
                "pu2:x:50402:50402:PolKit Test user 1:/home/polkittest2:/bin/bash\n"
                "pu3:x:50403:50403:PolKit Test user 2:/home/polkittest3:/bin/bash\n";
        const char test_pu1_run[] =
                "";
        const char test_pu1_lib[] =
                "scope=grant:action-id=org.freedesktop.policykit.read:when=1194634242:granted-by=0\n";
        const char test_pu2_run[] =
                "";
        const char test_pu2_lib[] =
                "";
        char test_pu3_run[512];
        const char test_pu3_lib[] =
                "";
        PolKitCaller *caller;
        PolKitAction *action;
        PolKitSession *session;
        polkit_bool_t is_auth;
        polkit_bool_t is_neg;
        PolKitError *error;
        polkit_uint64_t start_time;


        adb = NULL;
        caller = NULL;
        action = NULL;
        session = NULL;

        start_time = polkit_sysdeps_get_start_time_for_pid (getpid ());
        if (start_time == 0)
                goto out;
        
        if (snprintf (test_pu3_run, sizeof (test_pu3_run), 
                      "scope=process:pid=%d:pid-start-time=%lld:action-id=org.example.per-process:when=1196307507:auth-as=500\n"
                      "scope=process-one-shot:pid=%d:pid-start-time=%lld:action-id=org.example.per-process-one-shot:when=1196307507:auth-as=500\n"
                      "scope=session:session-id=%%2FSession1:action-id=org.example.per-session:when=1196307507:auth-as=500\n",
                      getpid (), start_time,
                      getpid (), start_time) >= (int) sizeof (test_pu3_run))
                goto fail;
        
        if (setenv ("POLKIT_TEST_LOCALSTATE_DIR", TEST_DATA_DIR "authdb-test", 1) != 0)
                goto fail;

        if (setenv ("POLKIT_TEST_BUILD_DIR", TEST_BUILD_DIR, 1) != 0)
                goto fail;

        if (setenv ("KIT_TEST_PASSWD_FILE", TEST_DATA_DIR "authdb-test/passwd", 1) != 0)
                goto fail;

        /* create test users */
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/passwd", 0644, 
                                    test_passwd, sizeof (test_passwd) - 1))
                goto out;

        /* seed the authdb with known defaults */
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/run/polkit-1/user-pu1.auths", 0644, 
                                    test_pu1_run, sizeof (test_pu1_run) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/lib/polkit-1/user-pu1.auths", 0644, 
                                    test_pu1_lib, sizeof (test_pu1_lib) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/run/polkit-1/user-pu2.auths", 0644, 
                                    test_pu2_run, sizeof (test_pu2_run) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/lib/polkit-1/user-pu2.auths", 0644, 
                                    test_pu2_lib, sizeof (test_pu2_lib) - 1))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/run/polkit-1/user-pu3.auths", 0644, 
                                    test_pu3_run, strlen (test_pu3_run)))
                goto out;
        if (!kit_file_set_contents (TEST_DATA_DIR "authdb-test/lib/polkit-1/user-pu3.auths", 0644, 
                                    test_pu3_lib, sizeof (test_pu3_lib) - 1))
                goto out;

        if ((adb = _polkit_authorization_db_new ()) == NULL)
                goto out;


        if ((action = polkit_action_new ()) == NULL)
                goto out;
        if ((caller = polkit_caller_new ()) == NULL)
                goto out;
        kit_assert (polkit_caller_set_pid (caller, getpid ()));

        /* initialize all pretend environment variables */
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_CK_SESSION_OBJPATH", "", 1) != 0)
                goto fail;

        /*
         * test: "org.freedesktop.policykit.read" 
         */
        if (!polkit_action_set_action_id (action, "org.freedesktop.policykit.read"))
                goto out;

        /* test: pu1 has the auth org.freedesktop.policykit.read */
        kit_assert (polkit_caller_set_uid (caller, 50401));
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50401", 1) != 0)
                goto fail;
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error) && is_auth && !is_neg);
        } else {
                //kit_warning ("%p: %d: %s: %s", 
                //             error, 
                //             polkit_error_get_error_code (error), 
                //             polkit_error_get_error_name (error),
                //             polkit_error_get_error_message (error));
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }

        /* test: pu2 does not have the auth org.freedesktop.policykit.read */
        kit_assert (polkit_caller_set_uid (caller, 50402));
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50402", 1) != 0)
                goto fail;
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error));
                kit_assert (!is_auth && !is_neg);
        } else {
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }

        /************************/
        /* INVALIDATE THE CACHE */
        /************************/
        _polkit_authorization_db_invalidate_cache (adb);

        /* test: pu1 can check that pu2 does not have the auth org.freedesktop.policykit.read */
        kit_assert (polkit_caller_set_uid (caller, 50402));
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50401", 1) != 0)
                goto fail;
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error) && !is_auth && !is_neg);
        } else {
                kit_warning ("%p: %d: %s: %s", 
                             error, 
                             polkit_error_get_error_code (error), 
                             polkit_error_get_error_name (error),
                             polkit_error_get_error_message (error));
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }

        /* test: pu2 cannot check if pu1 have the auth org.freedesktop.policykit.read */
        kit_assert (polkit_caller_set_uid (caller, 50401));
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50402", 1) != 0)
                goto fail;
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_warning ("pu2 shouldn't be able to read auths for pu1: %d %d", is_auth, is_neg);
                goto fail;
        } else {
                kit_assert (polkit_error_is_set (error) && 
                            (polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY ||
                             polkit_error_get_error_code (error) == POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS));
                polkit_error_free (error);
        }

        /* test: pu3 is authorized for org.example.per-process for just this process id */
        if (!polkit_action_set_action_id (action, "org.example.per-process"))
                goto out;

        kit_assert (polkit_caller_set_uid (caller, 50403));
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50403", 1) != 0)
                goto fail;
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error) && is_auth && !is_neg);
        } else {
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }

        /* test: pu3 is authorized for org.example.per-process-one-shot just once */
        if (!polkit_action_set_action_id (action, "org.example.per-process-one-shot"))
                goto out;

        kit_assert (polkit_caller_set_uid (caller, 50403));
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_UID", "50403", 1) != 0)
                goto fail;
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, TRUE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error) && is_auth && !is_neg);

                /************************/
                /* INVALIDATE THE CACHE */
                /************************/
                _polkit_authorization_db_invalidate_cache (adb);

                if (polkit_authorization_db_is_caller_authorized (adb, action, caller, TRUE, &is_auth, &is_neg, &error)) {
                        if (is_auth || is_neg) {
                                kit_warning ("pu3 shouldn't be authorized for something twice: %d %d", is_auth, is_neg);
                                goto fail;
                        }
                } else {
                        kit_assert (polkit_error_is_set (error));
                        kit_assert (polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                        polkit_error_free (error);
                }
        } else {
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }

        if ((session = polkit_session_new ()) == NULL)
                goto out;

        /* test: pu3 only in the right session is authorized for org.example.per-session */
        if (!polkit_action_set_action_id (action, "org.example.per-session"))
                goto out;

        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_CK_SESSION_OBJPATH", "/Session1", 1) != 0)
                goto fail;
        kit_assert (polkit_session_set_ck_is_local (session, TRUE));
        if (!polkit_session_set_ck_objref (session, "/Session1"))
                goto out;
        kit_assert (polkit_caller_set_ck_session (caller, session));
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error) && is_auth && !is_neg);
        } else {
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }
        
        if (setenv ("POLKIT_TEST_PRETEND_TO_BE_CK_SESSION_OBJPATH", "/Session2", 1) != 0)
                goto fail;
        if (!polkit_session_set_ck_objref (session, "/Session2"))
                goto out;
        kit_assert (polkit_session_set_ck_is_local (session, TRUE));
        kit_assert (polkit_caller_set_ck_session (caller, session));
        error = NULL;
        if (polkit_authorization_db_is_caller_authorized (adb, action, caller, FALSE, &is_auth, &is_neg, &error)) {
                kit_assert (! polkit_error_is_set (error) && !is_auth && !is_neg);
        } else {
                kit_assert (polkit_error_is_set (error) && 
                            polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        }
        
out:

        if (action != NULL)
                polkit_action_unref (action);

        if (caller != NULL)
                polkit_caller_unref (caller);

        if (session != NULL)
                polkit_session_unref (session);

        if (adb != NULL) {
                polkit_authorization_db_debug (adb);
                polkit_authorization_db_validate (adb);
                polkit_authorization_db_ref (adb);
                polkit_authorization_db_unref (adb);
                polkit_authorization_db_unref (adb);
        }

        if (unsetenv ("POLKIT_TEST_PRETEND_TO_BE_UID") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_PRETEND_TO_BE_CK_SESSION_OBJPATH") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_PRETEND_TO_BE_SELINUX_CONTEXT") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_PRETEND_TO_BE_PID") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_LOCALSTATE_DIR") != 0)
                goto fail;

        if (unsetenv ("POLKIT_TEST_BUILD_DIR") != 0)
                goto fail;

        if (unsetenv ("KIT_TEST_PASSWD_FILE") != 0)
                goto fail;

        return TRUE;
fail:
        return FALSE;
}


KitTest _test_authorization_db = {
        "polkit_authorization_db",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

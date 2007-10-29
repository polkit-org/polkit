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
 * @short_description: An interface to the database storing authorizations
 *
 * This class is used to represent entries in the authorization
 * database.
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
        GHashTable *uid_to_authlist;
};

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

static polkit_bool_t
_write_to_fd (int fd, const char *str, ssize_t str_len)
{
        polkit_bool_t ret;
        ssize_t written;

        ret = FALSE;

        written = 0;
        while (written < str_len) {
                ssize_t ret;
                ret = write (fd, str + written, str_len - written);
                if (ret < 0) {
                        if (errno == EAGAIN || errno == EINTR) {
                                continue;
                        } else {
                                goto out;
                        }
                }
                written += ret;
        }

        ret = TRUE;

out:
        return ret;
}

polkit_bool_t 
_polkit_authorization_db_auth_file_add (const char *root, polkit_bool_t transient, uid_t uid, char *str_to_add)
{
        int fd;
        char *contents;
        gsize contents_size;
        char *path;
        char *path_tmp;
        GError *error;
        polkit_bool_t ret;
        struct stat statbuf;
        struct passwd *pw;

        ret = FALSE;
        path = NULL;
        path_tmp = NULL;
        contents = NULL;

        pw = getpwuid (uid);
        if (pw == NULL) {
                g_warning ("cannot lookup user name for uid %d\n", uid);
                goto out;
        }

        path = g_strdup_printf ("%s/user-%s.auths", root, pw->pw_name);
        path_tmp = g_strdup_printf ("%s.XXXXXX", path);

        if (stat (path, &statbuf) != 0 && errno == ENOENT) {
                //fprintf (stderr, "path=%s does not exist (egid=%d): %m!\n", path, getegid ());

                g_free (path_tmp);
                path_tmp = path;
                path = NULL;

                /* Write a nice blurb if we're creating the file for the first time */

                contents = g_strdup_printf (
                        "# This file lists authorizations for user %s\n"
                        "%s"
                        "# \n"
                        "# File format may change at any time; do not rely on it. To manage\n"
                        "# authorizations use polkit-auth(1) instead.\n"
                        "\n",
                        pw->pw_name,
                        transient ? "# (these are temporary and will be removed on the next system boot)\n" : "");
                contents_size = strlen (contents);
        } else {
                error = NULL;
                if (!g_file_get_contents (path, &contents, &contents_size, &error)) {
                        g_warning ("Cannot read authorizations file %s: %s", path, error->message);
                        g_error_free (error);
                        goto out;
                }
        }

        if (path != NULL) {
                fd = mkstemp (path_tmp);
                if (fd < 0) {
                        fprintf (stderr, "Cannot create file '%s': %m\n", path_tmp);
                        goto out;
                }
                if (fchmod (fd, 0464) != 0) {
                        fprintf (stderr, "Cannot change mode for '%s' to 0460: %m\n", path_tmp);
                        close (fd);
                        unlink (path_tmp);
                        goto out;
                }
        } else {
                fd = open (path_tmp, O_RDWR|O_CREAT, 0464);
                if (fd < 0) {
                        fprintf (stderr, "Cannot create file '%s': %m\n", path_tmp);
                        goto out;
                }
        }

        if (!_write_to_fd (fd, contents, contents_size)) {
                g_warning ("Cannot write to temporary authorizations file %s: %m", path_tmp);
                close (fd);
                if (unlink (path_tmp) != 0) {
                        g_warning ("Cannot unlink %s: %m", path_tmp);
                }
                goto out;
        }
        if (!_write_to_fd (fd, str_to_add, strlen (str_to_add))) {
                g_warning ("Cannot write to temporary authorizations file %s: %m", path_tmp);
                close (fd);
                if (unlink (path_tmp) != 0) {
                        g_warning ("Cannot unlink %s: %m", path_tmp);
                }
                goto out;
        }
        close (fd);

        if (path != NULL) {
                if (rename (path_tmp, path) != 0) {
                        g_warning ("Cannot rename %s to %s: %m", path_tmp, path);
                        if (unlink (path_tmp) != 0) {
                                g_warning ("Cannot unlink %s: %m", path_tmp);
                        }
                        goto out;
                }
        }

        /* trigger a reload */
        if (utimes (PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload", NULL) != 0) {
                g_warning ("Error updating access+modification time on file '%s': %m\n", 
                           PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload");
        }

        ret = TRUE;

out:
        if (contents != NULL)
                g_free (contents);
        if (path != NULL)
                g_free (path);
        if (path_tmp != NULL)
                g_free (path_tmp);
        return ret;
}


/**
 * polkit_authorization_db_add_entry_process:
 * @authdb: the authorization database
 * @action: the action
 * @caller: the caller
 * @user_authenticated_as: the user that was authenticated
 *
 * Write an entry to the authorization database to indicate that the
 * given caller is authorized for the given action.
 *
 * Note that this function should only be used by
 * <literal>libpolkit-grant</literal> or other sufficiently privileged
 * processes that deals with managing authorizations. It should never
 * be used by mechanisms or applications. The caller must have
 * egid=polkituser and umask set so creating files with mode 0460 will
 * work.
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
                                                    uid_t                  user_authenticated_as)
{
        char *action_id;
        uid_t caller_uid;
        pid_t caller_pid;
        char *grant_line;
        polkit_bool_t ret;
        polkit_uint64_t pid_start_time;
        struct timeval now;
        PolKitAuthorizationConstraint *constraint;
        char cbuf[256];

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (caller != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &action_id))
                return FALSE;

        if (!polkit_caller_get_pid (caller, &caller_pid))
                return FALSE;

        if (!polkit_caller_get_uid (caller, &caller_uid))
                return FALSE;

        pid_start_time = polkit_sysdeps_get_start_time_for_pid (caller_pid);
        if (pid_start_time == 0)
                return FALSE;

        if (gettimeofday (&now, NULL) != 0) {
                g_warning ("Error calling gettimeofday: %m");
                return FALSE;
        }

        constraint = polkit_authorization_constraint_get_from_caller (caller);
        if (polkit_authorization_constraint_to_string (constraint, cbuf, sizeof (cbuf)) >= sizeof (cbuf)) {
                g_warning ("buffer for auth constraint is too small");
                return FALSE;
        }

        grant_line = g_strdup_printf ("process:%d:%Lu:%s:%Lu:%d:%s\n", 
                                      caller_pid, 
                                      pid_start_time, 
                                      action_id,
                                      (polkit_uint64_t) now.tv_sec,
                                      user_authenticated_as,
                                      cbuf);

        ret = _polkit_authorization_db_auth_file_add (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit", 
                                                      TRUE, 
                                                      caller_uid, 
                                                      grant_line);
        g_free (grant_line);
        return ret;
}

/**
 * polkit_authorization_db_add_entry_session:
 * @authdb: the authorization database
 * @action: the action
 * @caller: the caller
 * @user_authenticated_as: the user that was authenticated
 *
 * Write an entry to the authorization database to indicate that the
 * session for the given caller is authorized for the given action for
 * the remainer of the session.
 *
 * Note that this function should only be used by
 * <literal>libpolkit-grant</literal> or other sufficiently privileged
 * processes that deals with managing authorizations. It should never
 * be used by mechanisms or applications. The caller must have
 * egid=polkituser and umask set so creating files with mode 0460 will
 * work.
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
                                                    PolKitCaller          *caller,
                                                    uid_t                  user_authenticated_as)
{
        uid_t session_uid;
        char *action_id;
        char *grant_line;
        PolKitSession *session;
        char *session_objpath;
        polkit_bool_t ret;
        struct timeval now;
        PolKitAuthorizationConstraint *constraint;
        char cbuf[256];

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (caller != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &action_id))
                return FALSE;

        if (!polkit_caller_get_ck_session (caller, &session))
                return FALSE;

        if (!polkit_session_get_ck_objref (session, &session_objpath))
                return FALSE;

        if (!polkit_session_get_uid (session, &session_uid))
                return FALSE;

        constraint = polkit_authorization_constraint_get_from_caller (caller);
        if (polkit_authorization_constraint_to_string (constraint, cbuf, sizeof (cbuf)) >= sizeof (cbuf)) {
                g_warning ("buffer for auth constraint is too small");
                return FALSE;
        }

        if (gettimeofday (&now, NULL) != 0) {
                g_warning ("Error calling gettimeofday: %m");
                return FALSE;
        }

        grant_line = g_strdup_printf ("session:%s:%s:%Lu:%d:%s\n", 
                                      session_objpath,
                                      action_id,
                                      (polkit_uint64_t) now.tv_sec,
                                      user_authenticated_as,
                                      cbuf);

        ret = _polkit_authorization_db_auth_file_add (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit", 
                                                      TRUE, 
                                                      session_uid, 
                                                      grant_line);
        g_free (grant_line);
        return ret;
}

/**
 * polkit_authorization_db_add_entry_always:
 * @authdb: the authorization database
 * @action: the action
 * @caller: the caller
 * @user_authenticated_as: the user that was authenticated
 *
 * Write an entry to the authorization database to indicate that the
 * given user is authorized for the given action.
 *
 * Note that this function should only be used by
 * <literal>libpolkit-grant</literal> or other sufficiently privileged
 * processes that deals with managing authorizations. It should never
 * be used by mechanisms or applications. The caller must have
 * egid=polkituser and umask set so creating files with mode 0460 will
 * work.
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
                                                    PolKitCaller          *caller,
                                                    uid_t                  user_authenticated_as)
{
        uid_t uid;
        char *action_id;
        char *grant_line;
        polkit_bool_t ret;
        struct timeval now;
        PolKitAuthorizationConstraint *constraint;
        char cbuf[256];

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (caller != NULL, FALSE);

        if (!polkit_caller_get_uid (caller, &uid))
                return FALSE;

        if (!polkit_action_get_action_id (action, &action_id))
                return FALSE;

        if (gettimeofday (&now, NULL) != 0) {
                g_warning ("Error calling gettimeofday: %m");
                return FALSE;
        }

        constraint = polkit_authorization_constraint_get_from_caller (caller);
        if (polkit_authorization_constraint_to_string (constraint, cbuf, sizeof (cbuf)) >= sizeof (cbuf)) {
                g_warning ("buffer for auth constraint is too small");
                return FALSE;
        }

        grant_line = g_strdup_printf ("always:%s:%Lu:%d:%s\n", 
                                      action_id,
                                      (polkit_uint64_t) now.tv_sec,
                                      user_authenticated_as,
                                      cbuf);

        ret = _polkit_authorization_db_auth_file_add (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit", 
                                                      FALSE, 
                                                      uid, 
                                                      grant_line);
        g_free (grant_line);
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

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (auth != NULL, FALSE);

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

typedef struct {
        char *action_id;
        PolKitAuthorizationConstraint  *constraint;
} CheckDataGrant;

static polkit_bool_t 
_check_auth_for_grant (PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{
        uid_t pimp;
        polkit_bool_t ret;
        CheckDataGrant *cd = (CheckDataGrant *) user_data;

        ret = FALSE;

        if (strcmp (polkit_authorization_get_action_id (auth), cd->action_id) != 0)
                goto no_match;

        if (!polkit_authorization_was_granted_explicitly (auth, &pimp))
                goto no_match;

        if (!polkit_authorization_constraint_equal (polkit_authorization_get_constraint (auth), cd->constraint))
                goto no_match;

        ret = TRUE;

no_match:
        return ret;
}

/**
 * polkit_authorization_db_grant_to_uid:
 * @authdb: authorization database
 * @action: action
 * @uid: uid to grant to
 * @constraint: what constraint to put on the authorization
 * @error: return location for error
 *
 * Grants an authorization to a user for a specific action. This
 * requires the org.freedesktop.policykit.grant authorization.
 *
 * Returns: #TRUE if the authorization was granted, #FALSE otherwise
 * and error will be set
 *
 * Since: 0.7
 */
polkit_bool_t 
polkit_authorization_db_grant_to_uid (PolKitAuthorizationDB          *authdb,
                                      PolKitAction                   *action,
                                      uid_t                           uid,
                                      PolKitAuthorizationConstraint  *constraint,
                                      PolKitError                   **error)
{
        GError *g_error;
        char *helper_argv[6] = {PACKAGE_LIBEXEC_DIR "/polkit-explicit-grant-helper", NULL, NULL, NULL, NULL, NULL};
        gboolean ret;
        gint exit_status;
        char cbuf[256];
        CheckDataGrant cd;

        ret = FALSE;

        g_return_val_if_fail (authdb != NULL, FALSE);
        g_return_val_if_fail (action != NULL, FALSE);
        g_return_val_if_fail (constraint != NULL, FALSE);

        if (!polkit_action_get_action_id (action, &(cd.action_id))) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Given action does not have action_id set");
                goto out;
        }

        if (polkit_authorization_constraint_to_string (constraint, cbuf, sizeof (cbuf)) >= sizeof (cbuf)) {
                g_warning ("buffer for auth constraint is too small");
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "buffer for auth constraint is too small");
                goto out;
        }

        /* check if we have the auth already */
        cd.constraint = constraint;
        if (!polkit_authorization_db_foreach_for_uid (authdb,
                                                      uid, 
                                                      _check_auth_for_grant,
                                                      &cd,
                                                      error)) {
                /* happens if caller can't read auths of target user */
                if (error != NULL && polkit_error_is_set (*error)) {
                        goto out;
                }
        } else {
                /* so it did exist.. */
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_AUTHORIZATION_ALREADY_EXISTS, 
                                        "An authorization for uid %d for the action %s with constraint '%s' already exists",
                                        uid, cd.action_id, cbuf);
                goto out;
        }


        helper_argv[1] = cd.action_id;
        helper_argv[2] = cbuf;
        helper_argv[3] = "uid";
        helper_argv[4] = g_strdup_printf ("%d", uid);
        helper_argv[5] = NULL;

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
                                        "Error spawning explicit grant helper: %s",
                                        g_error->message);
                g_error_free (g_error);
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                g_warning ("Explicit grant helper crashed!");
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Explicit grant helper crashed!");
                goto out;
        } else if (WEXITSTATUS(exit_status) != 0) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_NOT_AUTHORIZED_TO_GRANT_AUTHORIZATION, 
                                        "uid %d is not authorized to grant authorization for action %s to uid %d (requires org.freedesktop.policykit.grant)",
                                        getuid (), cd.action_id, uid);
        } else {
                ret = TRUE;
        }
        
out:
        g_free (helper_argv[4]);
        return ret;

}

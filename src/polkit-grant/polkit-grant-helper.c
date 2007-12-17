/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant-helper.c : setgid polkituser grant helper for PolicyKit
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

/* TODO: FIXME: XXX: this code needs security review before it can be released! */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef POLKIT_AUTHFW_PAM
#include <security/pam_appl.h>
#endif

#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <utime.h>

#include <glib.h>

#include <polkit-dbus/polkit-dbus.h>
// #include <polkit/polkit-grant-database.h>

/* Development aid: define PGH_DEBUG to get debugging output. Do _NOT_
 * enable this in production builds; it may leak passwords and other
 * sensitive information.
 */
#undef PGH_DEBUG
/* #define PGH_DEBUG */

/* synopsis: polkit-grant-helper <pid> <action-name>
 *
 * <pid>           : process id of caller to grant privilege to
 * <action-name>   : the PolicyKit action
 *
 * Error/debug messages goes to stderr. Interaction with the program
 * launching this helper happens via stdin/stdout. A rough high-level
 * interaction diagram looks like this (120 character width):
 *
 *  Program using
 *  libpolkit-grant                    polkit-grant-helper                  polkit-grant-helper-pam
 *  -------------                      -------------------                  -----------------------
 *
 *   Spawn polkit-grant-helper
 *   with args <pid>, <action-name> -->
 *
 *                                   Create PolKitCaller object
 *                                   from <pid>. Involves querying
 *                                   ConsoleKit over the system
 *                                   message-bus. Verify that
 *                                   the caller qualifies for
 *                                   for authentication to gain
 *                                   the right to do the Action.
 *
 *                      <-- Tell libpolkit-grant about grant details, e.g.
 *                          {self,admin}_{,keep_session,keep_always} +
 *                          what users can authenticate using stdout
 *
 *   Receive grant details on stdin.
 *   Caller prepares UI dialog depending
 *   on grant details.
 *
 *                                     if admin_users is not empty, wait for
 *                                     user name of admin user to auth on stdin
 *
 *   if admin_users is not empty, write
 *   user name of admin user to auth on stdout -->
 *
 *
 *                                       verify that given username is
 *                                       in admin_users
 *
 *
 *                                       Spawn polkit-grant-helper-pam
 *                                       with no args -->
 *
 *                                       Write username to auth as
 *                                       on stdout -->
 *                                        
 *                                                                         Receive username on stdin.
 *                                                                         Start the PAM stack
 * auth_in_progess:
 *                                                                         Write a PAM request on stdout, one off
 *                                                                         - PAM_PROMPT_ECHO_OFF
 *                                                                         - PAM_PROMPT_ECHO_ON
 *                                                                         - PAM_ERROR_MSG
 *                                                                         - PAM_TEXT_INFO
 *
 *                                       Receive PAM request on stdin.
 *                                       Send it to libpolkit-grant on stdout
 *
 *   Receive PAM request on stdin.
 *   Program deals with it.
 *   Write reply on stdout
 *
 *                                       Receive PAM reply on stdin
 *                                       Send PAM reply on stdout
 *
 *                                                                         Deal with PAM reply on stdin.
 *                                                                         Now either
 *                                                                         - GOTO auth_in_progress; or
 *                                                                         - Write SUCCESS|FAILURE on stdout and then
 *                                                                           die
 *                                                                         
 *                                       Receive either SUCCESS or
 *                                       FAILURE on stdin. If FAILURE
 *                                       is received, then die with exit
 *                                       code 1. If SUCCESS, leave a cookie
 *                                       in /var/{lib,run}/PolicyKit indicating
 *                                       the grant was successful and die with
 *                                       exit code 0
 *
 *
 * If auth fails, we exit with code 1.
 * If input is not valid we exit with code 2.
 * If any other error occur we exit with code 3
 * If privilege was granted, we exit code 0.
 */


/** 
 * do_auth:
 * 
 * the authentication itself is done via a setuid root helper; this is
 * to make the code running as uid 0 easier to audit. 
 *
 */
static polkit_bool_t
do_auth (const char *user_to_auth, gboolean *empty_conversation)
{
        int helper_pid;
        int helper_stdin;
        int helper_stdout;
        GError *g_error;
#ifdef POLKIT_AUTHFW_PAM
        char *helper_argv[2] = {PACKAGE_LIBEXEC_DIR "/polkit-grant-helper-pam", NULL};
#endif
        char buf[256];
        FILE *child_stdin;
        FILE *child_stdout;
        gboolean ret;

        child_stdin = NULL;
        child_stdout = NULL;
        ret = FALSE;
        *empty_conversation = TRUE;

        g_error = NULL;
        if (!g_spawn_async_with_pipes (NULL,
                                       (char **) helper_argv,
                                       NULL,
                                       0,
                                       NULL,
                                       NULL,
                                       &helper_pid,
                                       &helper_stdin,
                                       &helper_stdout,
                                       NULL,
                                       &g_error)) {
                fprintf (stderr, "polkit-grant-helper: cannot spawn helper: %s\n", g_error->message);
                g_error_free (g_error);
                g_free (helper_argv[1]);
                goto out;
        }

        child_stdin = fdopen (helper_stdin, "w");
        if (child_stdin == NULL) {
                fprintf (stderr, "polkit-grant-helper: fdopen (helper_stdin) failed: %s\n", strerror (errno));
                goto out;
        }
        child_stdout = fdopen (helper_stdout, "r");
        if (child_stdout == NULL) {
                fprintf (stderr, "polkit-grant-helper: fdopen (helper_stdout) failed: %s\n", strerror (errno));
                goto out;
        }

        /* First, tell the pam helper what user we wish to auth */
        fprintf (child_stdin, "%s\n", user_to_auth);
        fflush (child_stdin);

        /* now act as middle man between our parent and our child */

        while (TRUE) {
                /* read from child */
                if (fgets (buf, sizeof buf, child_stdout) == NULL)
                        goto out;
#ifdef PGH_DEBUG
                fprintf (stderr, "received: '%s' from child; sending to parent\n", buf);
#endif /* PGH_DEBUG */
                /* see if we're done? */
                if (strcmp (buf, "SUCCESS\n") == 0) {
                        ret = TRUE;
                        goto out;
                }
                if (strcmp (buf, "FAILURE\n") == 0) {
                        goto out;
                }

                *empty_conversation = FALSE;

                /* send to parent */
                fprintf (stdout, buf);
                fflush (stdout);
                
                /* read from parent */
                if (fgets (buf, sizeof buf, stdin) == NULL)
                        goto out;

#ifdef PGH_DEBUG
                fprintf (stderr, "received: '%s' from parent; sending to child\n", buf);
#endif /* PGH_DEBUG */
                /* send to child */
                fprintf (child_stdin, buf);
                fflush (child_stdin);
        }

out:
        if (child_stdin != NULL)
                fclose (child_stdin);
        if (child_stdout != NULL)
                fclose (child_stdout);
        return ret;
}

/**
 * verify_with_polkit:
 * @caller: the caller
 * @action: the action
 * @out_result: return location for result AKA how the user can auth
 * @out_admin_users: return location for a NULL-terminated array of
 * strings that can be user to auth as admin. Is set to NULL if the
 * super user (e.g. uid 0) should be user to auth as admin.
 *
 * Verify that the given caller can authenticate to gain a privilege
 * to do the given action. If the authentication requires
 * administrator privileges, also return a list of users that can be
 * used to do this cf. the <define_admin_auth/> element in the
 * configuration file; see the PolicyKit.conf(5) manual page for
 * details.
 *
 * Returns: #TRUE if, and only if, the given caller can authenticate to
 * gain a privilege to do the given action.
 */
static polkit_bool_t
verify_with_polkit (PolKitContext *pol_ctx,
                    PolKitCaller *caller,
                    PolKitAction *action,
                    PolKitResult *out_result,
                    char ***out_admin_users)
{
        PolKitError *pk_error;

        pk_error = NULL;
        *out_result = polkit_context_is_caller_authorized (pol_ctx, action, caller, FALSE, &pk_error);
        if (polkit_error_is_set (pk_error)) {
                fprintf (stderr, "polkit-grant-helper: cannot determine if caller is authorized: %s: %s\n",
                         polkit_error_get_error_name (pk_error),
                         polkit_error_get_error_message (pk_error));
                polkit_error_free (pk_error);
                goto error;
        }

        if (*out_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT &&
            *out_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH &&
            *out_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION &&
            *out_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS &&
            *out_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT &&
            *out_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH &&
            *out_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION &&
            *out_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS) {
                fprintf (stderr, "polkit-grant-helper: given auth type (%d -> %s) is bogus\n", 
                         *out_result, polkit_result_to_string_representation (*out_result));
                goto error;
        }

        *out_admin_users = NULL;

        /* for admin auth, get a list of users that can be used - this is basically evaluating the
         * <define_admin_auth/> directives in the config file...
         */
        if (*out_result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT ||
            *out_result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH ||
            *out_result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION ||
            *out_result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS) {
                PolKitConfig *pk_config;
                PolKitConfigAdminAuthType admin_auth_type;
                const char *admin_auth_data;

                pk_config = polkit_context_get_config (pol_ctx, NULL);
                /* if the configuration file is malformed, bail out */
                if (pk_config == NULL)
                        goto error;

                if (polkit_config_determine_admin_auth_type (pk_config, 
                                                             action, 
                                                             caller, 
                                                             &admin_auth_type, 
                                                             &admin_auth_data)) {
#ifdef PGH_DEBUG
                        fprintf (stderr, "polkit-grant-helper: admin_auth_type=%d data='%s'\n", admin_auth_type, admin_auth_data);
#endif /* PGH_DEBUG */
                        switch (admin_auth_type) {
                        case POLKIT_CONFIG_ADMIN_AUTH_TYPE_USER:
                                if (admin_auth_data != NULL)
                                        *out_admin_users = g_strsplit (admin_auth_data, "|", 0);
                                break;
                        case POLKIT_CONFIG_ADMIN_AUTH_TYPE_GROUP:
                                if (admin_auth_data != NULL) {
                                        int n;
                                        char **groups;
                                        GSList *i;
                                        GSList *users;


                                        users = NULL;
                                        groups = g_strsplit (admin_auth_data, "|", 0);
                                        for (n = 0; groups[n] != NULL; n++)  {
                                                int m;
                                                struct group *group;

                                                /* This is fine; we're a single-threaded app */
                                                if ((group = getgrnam (groups[n])) == NULL)
                                                        continue;

                                                for (m = 0; group->gr_mem[m] != NULL; m++) {
                                                        const char *user;
                                                        gboolean found;

                                                        user = group->gr_mem[m];
                                                        found = FALSE;

#ifdef PGH_DEBUG
                                                        fprintf (stderr, "polkit-grant-helper: examining member '%s' of group '%s'\n", user, groups[n]);
#endif /* PGH_DEBUG */

                                                        /* skip user 'root' since he is often member of 'wheel' etc. */
                                                        if (strcmp (user, "root") == 0)
                                                                continue;
                                                        /* TODO: we should probably only consider users with an uid
                                                         * in a given "safe" range, e.g. between 500 and 32000 or
                                                         * something like that...
                                                         */

                                                        for (i = users; i != NULL; i = g_slist_next (i)) {
                                                                if (strcmp (user, (const char *) i->data) == 0) {
                                                                        found = TRUE;
                                                                        break;
                                                                }
                                                        }
                                                        if (found)
                                                                continue;

#ifdef PGH_DEBUG
                                                        fprintf (stderr, "polkit-grant-helper: added user '%s'\n", user);
#endif /* PGH_DEBUG */

                                                        users = g_slist_prepend (users, g_strdup (user));
                                                }

                                        }
                                        g_strfreev (groups);

                                        users = g_slist_sort (users, (GCompareFunc) strcmp);

                                        *out_admin_users = g_new0 (char *, g_slist_length (users) + 1);
                                        for (i = users, n = 0; i != NULL; i = g_slist_next (i)) {
                                                (*out_admin_users)[n++] = i->data;
                                        }

                                        g_slist_free (users);
                                }
                                break;
                        }
                }
        }
        

        /* TODO: we should probably clean up */

        return TRUE;
error:
        return FALSE;
}

static polkit_bool_t
get_and_validate_override_details (PolKitResult *result)
{
        char buf[256];
        char *textual_result;
        PolKitResult desired_result;

        if (fgets (buf, sizeof buf, stdin) == NULL)
                goto error;
        if (strlen (buf) > 0 &&
            buf[strlen (buf) - 1] == '\n')
                buf[strlen (buf) - 1] = '\0';

        if (strncmp (buf, 
                     "POLKIT_GRANT_CALLER_PASS_OVERRIDE_GRANT_TYPE ", 
                     sizeof "POLKIT_GRANT_CALLER_PASS_OVERRIDE_GRANT_TYPE " - 1) != 0) {
                goto error;
        }
        textual_result = buf + sizeof "POLKIT_GRANT_CALLER_PASS_OVERRIDE_GRANT_TYPE " - 1;

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: caller said '%s'\n", textual_result);
#endif /* PGH_DEBUG */

        if (!polkit_result_from_string_representation (textual_result, &desired_result))
                goto error;

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: testing for voluntarily downgrade from '%s' to '%s'\n",
                 polkit_result_to_string_representation (*result),
                 polkit_result_to_string_representation (desired_result));
#endif /* PGH_DEBUG */

        /* See the huge comment in main() below... 
         *
         * it comes down to this... users can only choose a more restricted granting type...
         */
        switch (*result) {
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS)
                        goto error;
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS)
                        goto error;
                break;

        default:
                /* we should never reach this */
                goto error;
        }

#ifdef PGH_DEBUG
        if (*result != desired_result) {
                fprintf (stderr, "polkit-grant-helper: voluntarily downgrading from '%s' to '%s'\n",
                         polkit_result_to_string_representation (*result),
                         polkit_result_to_string_representation (desired_result));
        }
#endif /* PGH_DEBUG */

        *result = desired_result;

        return TRUE;
error:
        return FALSE;
}

int
main (int argc, char *argv[])
{
        int ret;
        uid_t invoking_user_id;
        pid_t caller_pid;
        gid_t egid;
        struct group *group;
        char *endp;
        const char *invoking_user_name;
        const char *action_name;
        PolKitResult result;
        PolKitResult orig_result;
        const char *user_to_auth;
        uid_t uid_of_user_to_auth;
        char *session_objpath;
        struct passwd *pw;
        polkit_bool_t dbres;
        char **admin_users;
        DBusError error;
        DBusConnection *bus;
        PolKitContext *context;
        PolKitAction *action;
        PolKitCaller *caller;
        uid_t caller_uid;
        PolKitSession *session;
        gboolean empty_conversation;

        ret = 3;

        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (clearenv () != 0)
                goto out;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        openlog ("polkit-grant-helper", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (argc != 3) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-grant-helper: wrong number of arguments. This incident has been logged.\n");
                goto out;
        }

        /* check we're running with a non-tty stdin */
        if (isatty (STDIN_FILENO) != 0) {
                syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                fprintf (stderr, "polkit-grant-helper: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                goto out;
        }

        /* check user */
        invoking_user_id = getuid ();
        if (invoking_user_id == 0) {
                fprintf (stderr, "polkit-grant-helper: it only makes sense to run polkit-grant-helper as non-root\n");
                goto out;
        }

        /* check that we are setgid polkituser */
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "polkit-grant-helper: cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) != 0) {
                fprintf (stderr, "polkit-grant-helper: needs to be setgid " POLKIT_GROUP "\n");
                goto out;
        }

        pw = getpwuid (invoking_user_id);
        if (pw == NULL) {
                fprintf (stderr, "polkit-grant-helper: cannot lookup passwd info for uid %d\n", invoking_user_id);
                goto out;
        }
        invoking_user_name = strdup (pw->pw_name);
        if (invoking_user_name == NULL) {
                fprintf (stderr, "polkit-grant-helper: OOM allocating memory for invoking user name\n");
                goto out;
        }

        caller_pid = strtol (argv[1], &endp, 10);
        if (endp == NULL || endp == argv[1] || *endp != '\0') {
                fprintf (stderr, "polkit-grant-helper: cannot parse pid\n");
                goto out;
        }
        action_name = argv[2];

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: invoking user   = %d ('%s')\n", invoking_user_id, invoking_user_name);
        fprintf (stderr, "polkit-grant-helper: caller_pid      = %d\n", caller_pid);
        fprintf (stderr, "polkit-grant-helper: action_name     = '%s'\n", action_name);
#endif /* PGH_DEBUG */

        ret = 2;

        context = polkit_context_new ();
        if (!polkit_context_init (context, NULL)) {
                fprintf (stderr, "polkit-grant-helper: cannot initialize polkit\n");
                goto out;
        }

        action = polkit_action_new ();
        polkit_action_set_action_id (action, action_name);

        dbus_error_init (&error);
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                fprintf (stderr, "polkit-grant-helper: cannot connect to system bus: %s: %s\n", 
                         error.name, error.message);
                dbus_error_free (&error);
                goto out;
        }

        caller = polkit_caller_new_from_pid (bus, caller_pid, &error);
        if (caller == NULL) {
                fprintf (stderr, "polkit-grant-helper: cannot get caller from pid: %s: %s\n",
                         error.name, error.message);
                goto out;
        }
        if (!polkit_caller_get_uid (caller, &caller_uid)) {
                fprintf (stderr, "polkit-grant-helper: no uid for caller\n");
                goto out;
        }

        /* This user does not have to be in a session.. for example, one might 
         * use <allow_any>auth_admin</allow_any>...
         */
        session = NULL;
        session_objpath = NULL;
        if (polkit_caller_get_ck_session (caller, &session) && session != NULL) {
                if (!polkit_session_get_ck_objref (session, &session_objpath)) {
                        session = NULL;
                        session_objpath = NULL;
                }
        }

        /* Use libpolkit to figure out if the caller can really auth to do the action
         */
        if (!verify_with_polkit (context, caller, action, &result, &admin_users))
                goto out;

#ifdef PGH_DEBUG
        if (admin_users != NULL) {
                int n;
                fprintf (stderr, "polkit-grant-helper: admin_users: ");
                for (n = 0; admin_users[n] != NULL; n++)
                        fprintf (stderr, "'%s' ", admin_users[n]);
                fprintf (stderr, "\n");
        }
#endif /* PGH_DEBUG */

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: polkit result   = '%s'\n", 
                 polkit_result_to_string_representation (result));
        fprintf (stderr, "polkit-grant-helper: session_objpath = '%s'\n", session_objpath);
#endif /* PGH_DEBUG */

        /* tell the caller about the grant details; e.g. whether
         * it's auth_self_keep_always or auth_self etc.
         */
        fprintf (stdout, "POLKIT_GRANT_HELPER_TELL_TYPE %s\n", 
                 polkit_result_to_string_representation (result));
        fflush (stdout);

        /* if admin auth is required, tell caller about possible users */
        if (admin_users != NULL) {
                int n;
                fprintf (stdout, "POLKIT_GRANT_HELPER_TELL_ADMIN_USERS");
                for (n = 0; admin_users[n] != NULL; n++)
                        fprintf (stdout, " %s", admin_users[n]);
                fprintf (stdout, "\n");
                fflush (stdout);
        }


        /* wait for libpolkit-grant to tell us what user to use */
        if (admin_users != NULL) {
                int n;
                char buf[256];

#ifdef PGH_DEBUG
                fprintf (stderr, "waiting for admin user name...\n");
#endif /* PGH_DEBUG */

                /* read from parent */
                if (fgets (buf, sizeof buf, stdin) == NULL)
                        goto out;
                if (strlen (buf) > 0 && buf[strlen (buf) - 1] == '\n')
                        buf[strlen (buf) - 1] = '\0';

                if (strncmp (buf, 
                             "POLKIT_GRANT_CALLER_SELECT_ADMIN_USER ", 
                             sizeof "POLKIT_GRANT_CALLER_SELECT_ADMIN_USER " - 1) != 0) {
                        goto out;
                }

                user_to_auth = strdup (buf) + sizeof "POLKIT_GRANT_CALLER_SELECT_ADMIN_USER " - 1;
#ifdef PGH_DEBUG
                fprintf (stderr, "libpolkit-grant wants to auth as '%s'\n", user_to_auth);
#endif /* PGH_DEBUG */

                /* now sanity check that returned user is actually in admin_users */
                for (n = 0; admin_users[n] != NULL; n++) {
                        if (strcmp (admin_users[n], user_to_auth) == 0)
                                break;
                }
                if (admin_users[n] == NULL) {
                        ret = 2;
                        goto out;
                }

        } else {
                /* figure out what user to auth */
                if (result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT ||
                    result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH ||
                    result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION ||
                    result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS) {
                        user_to_auth = "root";
                } else {
                        user_to_auth = invoking_user_name;
                }
        }

        if (strcmp (user_to_auth, "root") == 0) {
                uid_of_user_to_auth = 0;
        } else {
                struct passwd *passwd;

                passwd = getpwnam (user_to_auth);
                if (passwd == NULL) {
                        fprintf (stderr, "polkit-grant-helper: can not look up uid for user '%s'\n", user_to_auth);
                        goto out;
                }
                uid_of_user_to_auth = passwd->pw_uid;
        }

        ret = 1;

        /* Start authentication */
        if (!do_auth (user_to_auth, &empty_conversation)) {
                goto out;
        }

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: empty_conversation=%d\n", empty_conversation);
#endif /* PGH_DEBUG */

        /* Ask caller if he want to slim down grant type...  e.g. he
         * might want to go from auth_self_keep_always to
         * auth_self_keep_session..
         *
         * See docs for the PolKitGrantOverrideGrantType callback type
         * for use cases; it's in polkit-grant/polkit-grant.h
         */
        fprintf (stdout, "POLKIT_GRANT_HELPER_ASK_OVERRIDE_GRANT_TYPE %s\n", 
                 polkit_result_to_string_representation (result));
        fflush (stdout);

        orig_result = result;
        if (!get_and_validate_override_details (&result)) {
                /* if this fails it means bogus input from user */
                ret = 2;
                goto out;
        }

        if (empty_conversation && orig_result == result) {
                /* If the conversation was empty it means the user probably never 
                 * saw the an auth dialog.. specifically it means he never was able
                 * to change the scope of the from e.g. 'always' to 'session' or 
                 * 'process'. In fact, it means he was never aware any authorization
                 * was granted. 
                 *
                 * So to avoid surprises for people who do reckless things like play
                 * around with disabling passwords on their system, make an executive
                 * decision to downgrade the scope... 
                 *
                 * See RH #401811 for details of one user that was caught by this.
                 */

                if (result == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS) {
                        result = POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION;
                } else if (result == POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS) {
                        result = POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION;
                }
        }


#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: adding grant: action_id=%s session_id=%s pid=%d result='%s'\n", 
                 action_name, session_objpath, caller_pid, polkit_result_to_string_representation (result));
#endif /* PGH_DEBUG */

        /* make sure write permissions for group is honored */
        umask (002);

        switch (result) {
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_ONE_SHOT:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_ONE_SHOT:
                dbres = polkit_authorization_db_add_entry_process_one_shot (polkit_context_get_authorization_db (context), 
                                                                            action, 
                                                                            caller,
                                                                            uid_of_user_to_auth);
                if (dbres) {
                        syslog (LOG_INFO, "granted one shot authorization for %s to pid %d [uid=%d] [auth=%s]",
                                action_name, caller_pid, invoking_user_id, user_to_auth);
                }
                break;

        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
                dbres = polkit_authorization_db_add_entry_process (polkit_context_get_authorization_db (context), 
                                                                   action, 
                                                                   caller,
                                                                   uid_of_user_to_auth);
                if (dbres) {
                        syslog (LOG_INFO, "granted authorization for %s to pid %d [uid=%d] [auth=%s]",
                                action_name, caller_pid, invoking_user_id, user_to_auth);
                }
                break;

        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
                if (session == NULL || session_objpath == NULL) {
                        fprintf (stderr, "polkit-grant-helper: cannot grant to session when not in a session\n");
                        ret = 2;
                        goto out;
                }
                dbres = polkit_authorization_db_add_entry_session (polkit_context_get_authorization_db (context), 
                                                                   action, 
                                                                   caller,
                                                                   uid_of_user_to_auth);

                if (dbres) {
                        syslog (LOG_INFO, "granted authorization for %s to session %s [uid=%d] [auth=%s]",
                                action_name, session_objpath, invoking_user_id, user_to_auth);
                }
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS:
                dbres = polkit_authorization_db_add_entry_always (polkit_context_get_authorization_db (context), 
                                                                  action, 
                                                                  caller,
                                                                  uid_of_user_to_auth);
                if (dbres) {
                        syslog (LOG_INFO, "granted authorization for %s to uid %d [auth=%s]", 
                                action_name, caller_uid, user_to_auth);
                }
                break;

        default:
                /* should never happen */
                goto out;
        }

        if (!dbres) {
                fprintf (stderr, "polkit-grant-helper: failed to write to grantdb\n");
                goto out;
        }

        ret = 0;
out:
#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper: exiting with code %d\n", ret);
#endif /* PGH_DEBUG */
        return ret;
}

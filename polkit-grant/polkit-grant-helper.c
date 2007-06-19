/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant-helper.c : setgid grant helper for PolicyKit
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
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
#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>

#include <glib.h>

#include <polkit-dbus/polkit-dbus.h>

#include "polkit-grant-database.h"

static int
conversation_function (int n,
                       const struct pam_message **msg,
                       struct pam_response **resp,
                       void *data)
{
        struct pam_response *aresp;
        char buf[PAM_MAX_RESP_SIZE];
        int i;

        data = data;
        if (n <= 0 || n > PAM_MAX_NUM_MSG)
                return PAM_CONV_ERR;

        if ((aresp = calloc(n, sizeof *aresp)) == NULL)
                return PAM_BUF_ERR;

        for (i = 0; i < n; ++i) {
                aresp[i].resp_retcode = 0;
                aresp[i].resp = NULL;
                switch (msg[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                        fprintf (stdout, "PAM_PROMPT_ECHO_OFF ");
                        goto conv1;
                case PAM_PROMPT_ECHO_ON:
                        fprintf (stdout, "PAM_PROMPT_ECHO_ON ");
                conv1:
                        fputs (msg[i]->msg, stdout);
                        if (strlen (msg[i]->msg) > 0 &&
                            msg[i]->msg[strlen (msg[i]->msg) - 1] != '\n')
                                fputc ('\n', stdout);
                        fflush (stdout);

                        if (fgets (buf, sizeof buf, stdin) == NULL)
                                goto error;
                        if (strlen (buf) > 0 &&
                            buf[strlen (buf) - 1] == '\n')
                                buf[strlen (buf) - 1] = '\0';

                        aresp[i].resp = strdup (buf);
                        if (aresp[i].resp == NULL)
                                goto error;
                        break;

                case PAM_ERROR_MSG:
                        fprintf (stdout, "PAM_ERROR_MSG ");
                        goto conv2;

                case PAM_TEXT_INFO:
                        fprintf (stdout, "PAM_TEXT_INFO ");
                conv2:
                        fputs(msg[i]->msg, stdout);
                        if (strlen(msg[i]->msg) > 0 &&
                            msg[i]->msg[strlen (msg[i]->msg) - 1] != '\n')
                                fputc ('\n', stdout);

                        fflush (stdout);
                        break;
                default:
                        goto error;
                }
        }
        *resp = aresp;
        return PAM_SUCCESS;

error:
        for (i = 0; i < n; ++i) {
                if (aresp[i].resp != NULL) {
                        memset (aresp[i].resp, 0, strlen(aresp[i].resp));
                        free (aresp[i].resp);
                }
        }
        memset (aresp, 0, n * sizeof *aresp);
        *resp = NULL;
        return PAM_CONV_ERR;
}

static polkit_bool_t
do_auth (const char *user_to_auth)
{
	struct pam_conv pam_conversation;
	pam_handle_t *pam_h;
        const void *authed_user;
	int rc;

	pam_conversation.conv        = conversation_function;
	pam_conversation.appdata_ptr = NULL;

        /* start the pam stack */
	rc = pam_start ("polkit",
			user_to_auth, 
			&pam_conversation,
			&pam_h);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "pam_start failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

	/* is user really user? */
	rc = pam_authenticate (pam_h, 0);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "pam_authenticated failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

#if 0
        /* Hmm, this fails; TODO: investigate */

	/* permitted access? */
	rc = pam_acct_mgmt (pam_h, 0);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "pam_acct_mgmt failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}
#endif

        /* did we auth the right user? */
	rc = pam_get_item (pam_h, PAM_USER, &authed_user);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "pam_get_item failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

	if (strcmp (authed_user, user_to_auth) != 0) {
                fprintf (stderr, "Tried to auth user '%s' but we got auth for user '%s' instead",
                         user_to_auth, (const char *) authed_user);
		goto error;
	}

        return TRUE;
        /* TODO: we should probably clean up */
error:
        return FALSE;
}

static polkit_bool_t
verify_with_polkit (const char *dbus_name,
                    pid_t caller_pid,
                    const char *action_name,
                    PolKitResult *result,
                    char **out_session_objpath)
{
        PolKitCaller *caller;
        PolKitSession *session;
        char *str;
        DBusConnection *bus;
        DBusError error;
        PolKitContext *pol_ctx;
        PolKitAction *action;

        dbus_error_init (&error);
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                fprintf (stderr, "cannot connect to system bus: %s: %s\n", error.name, error.message);
                dbus_error_free (&error);
                goto out;
        }

        action = polkit_action_new ();
        polkit_action_set_action_id (action, action_name);

        if (dbus_name != NULL && strlen (dbus_name) > 0) {
                caller = polkit_caller_new_from_dbus_name (bus, dbus_name, &error);
                if (caller == NULL) {
                        fprintf (stderr, "cannot get caller from dbus name\n");
                        goto out;
                }
        } else {
                caller = polkit_caller_new_from_pid (bus, caller_pid, &error);
                if (caller == NULL) {
                        fprintf (stderr, "cannot get caller from pid\n");
                        goto out;
                }
        }

        if (!polkit_caller_get_ck_session (caller, &session)) {
                fprintf (stderr, "caller is not in a session\n");
                goto out;
        }
        if (!polkit_session_get_ck_objref (session, &str)) {
                fprintf (stderr, "cannot get session ck objpath\n");
                goto out;
        }
        *out_session_objpath = g_strdup (str);
        if (*out_session_objpath == NULL)
                goto out;

        //polkit_caller_debug (caller);

        pol_ctx = polkit_context_new ();
        if (!polkit_context_init (pol_ctx, NULL)) {
                fprintf (stderr, "cannot init polkit\n");
                goto out;
        }

        *result = polkit_context_can_caller_do_action (pol_ctx, action, caller);

        if (*result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH &&
            *result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION &&
            *result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS &&
            *result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH &&
            *result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION &&
            *result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS) {
                fprintf (stderr, "given auth type (%d -> %s) is bogus\n", 
                         *result, polkit_result_to_string_representation (*result));
                goto out;
        }

        return TRUE;
        /* TODO: we should probably clean up */
out:
        return FALSE;
}

static polkit_bool_t
get_and_validate_override_details (PolKitResult *result)
{
        char buf[256];
        PolKitResult desired_result;

        if (fgets (buf, sizeof buf, stdin) == NULL)
                goto error;
        if (strlen (buf) > 0 &&
            buf[strlen (buf) - 1] == '\n')
                buf[strlen (buf) - 1] = '\0';
        
        fprintf (stderr, "User said '%s'\n", buf);

        if (!polkit_result_from_string_representation (buf, &desired_result))
                goto error;

        fprintf (stderr, "Testing for voluntarily downgrade from '%s' to '%s'\n",
                 polkit_result_to_string_representation (*result),
                 polkit_result_to_string_representation (desired_result));

        /* See the huge comment in main() below... 
         *
         * it comes down to this... users can only choose a more restricted granting type...
         *
         */
        switch (*result) {
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS)
                        goto error;
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION)
                        goto error;
                break;
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
                if (desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION &&
                    desired_result != POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS)
                        goto error;
                break;

        default:
                /* we should never reach this */
                goto error;
        }

        if (*result != desired_result) {
                fprintf (stderr, "Voluntarily downgrading from '%s' to '%s'\n",
                         polkit_result_to_string_representation (*result),
                         polkit_result_to_string_representation (desired_result));
        }

        *result = desired_result;

        return TRUE;
error:
        return FALSE;
}

/* synopsis: polkit-grant-helper <auth-type> <dbus-name> <pid> <action-name>
 *
 * <dbus-name>     : unique name of caller on the system message bus to grant privilege to (may be blank)
 * <pid>           : process id of caller to grant privilege to
 * <action-name>   : the PolicyKit action
 *
 * PAM interaction happens via stdin/stdout.
 *
 * If auth fails, we exit with code 1.
 * If input is not valid we exit with code 2.
 * If any other error occur we exit with code 3
 * If privilege was grant, we exit code 0.
 */

int
main (int argc, char *argv[])
{
        int ret;
        uid_t invoking_user_id;
        pid_t caller_pid;
        const char *invoking_user_name;
        const char *dbus_name;
        const char *action_name;
        PolKitResult result;
        const char *user_to_auth;
        char *session_objpath;
        gid_t egid;
        struct group *group;
        struct passwd *pw;
        polkit_bool_t dbres;

        ret = 3;

        if (argc != 4) {
                fprintf (stderr, "wrong use\n");
                goto out;
        }

        /* check user */
        invoking_user_id = getuid ();
        if (invoking_user_id == 0) {
                fprintf (stderr, "it only makes sense to run polkit-grant-helper as non-root\n");
                goto out;
        }
        pw = getpwuid (invoking_user_id);
        if (pw == NULL) {
                fprintf (stderr, "cannot lookup passwd info for uid %d\n", invoking_user_id);
                goto out;
        }
        invoking_user_name = strdup (pw->pw_name);
        if (invoking_user_name == NULL) {
                fprintf (stderr, "OOM allocating memory for invoking user name\n");
                goto out;
        }

        fprintf (stderr, "invoking user '%s'\n", invoking_user_name);

        /* check group */
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) != 0) {
                fprintf (stderr, "polkit-grant-helper needs to be setgid " POLKIT_GROUP "\n");
                goto out;
        }

        fprintf (stderr, "Hello world %d %d %d %d!\n", getuid(), geteuid(), getgid(), getegid());

        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (clearenv () != 0)
                goto out;
        /* hmm; seems like some library (libdbus) don't like environ==NULL .. TODO: file bug */
        setenv ("PATH", "/bin:/usr/bin", 1);

        dbus_name = argv[1];
        caller_pid = atoi(argv[2]); /* TODO: use safer function? */
        action_name = argv[3];

        fprintf (stderr, "dbus_name = %s\n", dbus_name);
        fprintf (stderr, "caller_pid = %d\n", caller_pid);
        fprintf (stderr, "action_name = %s\n", action_name);

        ret = 2;

        /* we don't trust the user one bit...so..
         * 
         * verify that the given thing to auth for really supports grant by auth in the requested way
         */
        if (!verify_with_polkit (dbus_name, caller_pid, action_name, &result, &session_objpath))
                goto out;

        /* tell user about the grant details; e.g. whether it's auth_self_keep_always or auth_self etc. */
        fprintf (stdout, "POLKIT_GRANT_HELPER_TELL_TYPE %s\n", polkit_result_to_string_representation (result));
        fflush (stdout);

        /* figure out what user to auth */
        if (result == POLKIT_RESULT_ONLY_VIA_ROOT_AUTH ||
            result == POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION ||
            result == POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS) {
                user_to_auth = "root";
        } else {
                user_to_auth = invoking_user_name;
        }

        ret = 1;

        /* OK, start auth! */
        if (!do_auth (user_to_auth))
                goto out;

        /* ask user if he want to slim down grant type... 
         * e.g. he might want to go from auth_self_keep_always to auth_self_keep_session..
         *
         * See docs for the PolKitGrantOverrideGrantType callback type for use cases.
         */
        fprintf (stdout, "POLKIT_GRANT_HELPER_ASK_OVERRIDE_GRANT_TYPE %s\n", 
                 polkit_result_to_string_representation (result));
        fflush (stdout);
        
        if (!get_and_validate_override_details (&result)) {
                /* if this fails it means bogus input from user */
                ret = 2;
                goto out;
        }

        fprintf (stderr, "OK; TODO: write to database: action_id=%s session_id=%s pid=%d\n", 
                 action_name, session_objpath, caller_pid);

        switch (result) {
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
                dbres = _polkit_grantdb_write_pid (action_name, caller_pid);
                break;

        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
                dbres = _polkit_grantdb_write_keep_session (action_name, session_objpath);
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS:
                dbres = _polkit_grantdb_write_keep_always (action_name, invoking_user_id);
                break;

        default:
                /* should never happen */
                goto out;
        }

        if (!dbres) {
                fprintf (stderr, "polkit-grant-helper: failed to write to grantdb\n");
                goto out;
        }

#if 0
        /* TODO: FIXME: XXX: this format of storing granted privileges needs be redone
         *
         * this concerns these two files
         * - polkit-grant/polkit-grant-helper.c
         * - modules/grant/polkit-module-grant.c
         */

        /*
         * /var/lib/PolicyKit/uid_<uid>_<action>_<resource-hash>.grant
         *                    uid_<uid>_<action>.grant
         *
         * /var/run/PolicyKit/session_<session>_<uid>_<action>_<resource-hash>.grant
         *                    session_<session>_<uid>_<action>.grant
         *                    dbus_<dbusname>_<uid>_<action>_<resource-hash>.grant
         */

        char *grant_file;
        const char *session_name;
        char *resource_str_to_hash;
        guint resource_hash;
        session_name = g_basename (session_objpath);
        resource_str_to_hash = g_strdup_printf ("%s:%s", resource_type, resource_name);
        resource_hash = g_str_hash (resource_str_to_hash);
        g_free (resource_str_to_hash);

        switch (result) {
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
                grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/dbus_%s_%d_%s_%u.grant", 
                                              dbus_name, invoking_user_id, action_name, resource_hash);
                break;

        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
                grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/session_%s_%d_%s_%u.grant", 
                                              session_name, invoking_user_id, action_name, resource_hash);
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
        case POLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS:
                grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit/uid_%d_%s_%u.grant", 
                                              invoking_user_id, action_name, resource_hash);
                break;
        default:
                /* should never happen */
                goto out;
        }

        umask (~0464);
        fprintf (stderr, "file is '%s'\n", grant_file);
        FILE *f = fopen (grant_file, "w");
        fclose (f);
#endif

        ret = 0;
out:
        fprintf (stderr, "exiting with code %d\n", ret);
        return ret;
}

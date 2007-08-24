/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant.c : grant privileges to a user through authentication
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>

#include <polkit-dbus/polkit-dbus.h>
#include <polkit-grant/polkit-grant.h>
#include <polkit/polkit-grant-database.h>

#include <glib.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : polkit-grant [--gain <action>] [--list] [--delete <user>]\n"
                 "          [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --gain       Attempt to gain the privilege to do an action\n"
                 "        --list       List all grants\n"
                 "        --delete     Delete all grants for a given user\n"
                 "        --version    Show version and exit\n"
                 "        --help       Show this information and exit\n"
                 "\n");
}

typedef struct {
        gboolean gained_privilege;
        GMainLoop *loop;
} UserData;

static void
conversation_type (PolKitGrant *polkit_grant, PolKitResult auth_type, void *user_data)
{
        switch (auth_type) {
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH:
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS:
                printf ("Authentication as an administrative user is required.\n");
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
                printf ("Authentication is required.\n");
                break;

        default:
                /* should never happen */
                exit (1);
        }
}

static char *
conversation_select_admin_user (PolKitGrant *polkit_grant, char **admin_users, void *user_data)
{
        int n;
        char *user;
        char *lineptr = NULL;
        size_t linelen = 0;

        printf ("The following users qualify as administrative users:\n");
        for (n = 0; admin_users[n] != NULL; n++) {
                printf ("%s\n", admin_users[n]);
        }
        printf ("Select user: ");
        getline (&lineptr, &linelen, stdin);
        user = strdup (lineptr);
        free (lineptr);
        return user;
}

static char *
conversation_pam_prompt_echo_off (PolKitGrant *polkit_grant, const char *request, void *user_data)
{
        char *lineptr = NULL;
        size_t linelen = 0;
        struct termios old, new;
        char *result;

        printf ("%s", request);

        /* Turn echo off */
        if (tcgetattr (fileno (stdout), &old) != 0) {
                exit (1);
        }
        new = old;
        new.c_lflag &= ~ECHO;
        if (tcsetattr (fileno (stdout), TCSAFLUSH, &new) != 0) {
                exit (1);
        }

        getline (&lineptr, &linelen, stdin);
  
        /* Restore terminal. */
        tcsetattr (fileno (stdout), TCSAFLUSH, &old);

        result = strdup (lineptr);
        free (lineptr);
        printf ("\n");
        return result;
}

static char *
conversation_pam_prompt_echo_on (PolKitGrant *polkit_grant, const char *request, void *user_data)
{
        char *lineptr = NULL;
        size_t linelen = 0;
        char *result;
        printf ("%s", request);
        getline (&lineptr, &linelen, stdin);
        result = strdup (lineptr);
        free (lineptr);
        printf ("\n");
        return result;
}

static void
conversation_pam_error_msg (PolKitGrant *polkit_grant, const char *msg, void *user_data)
{
        printf ("error_msg='%s'\n", msg);
}

static void
conversation_pam_text_info (PolKitGrant *polkit_grant, const char *msg, void *user_data)
{
        printf ("text_info='%s'\n", msg);
}

static PolKitResult
conversation_override_grant_type (PolKitGrant *polkit_grant, PolKitResult auth_type, void *user_data)
{
        char *lineptr = NULL;
        size_t linelen = 0;
        polkit_bool_t keep_session = FALSE;
        polkit_bool_t keep_always = FALSE;
        PolKitResult overridden_auth_type;

        switch (auth_type) {
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
                break;
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
                printf ("Keep this privilege for the session? [no/session]?\n");
                getline (&lineptr, &linelen, stdin);
                if (g_str_has_prefix (lineptr, "no")) {
                        ;
                } else if (g_str_has_prefix (lineptr, "session")) {
                        keep_session = TRUE;
                } else {
                        printf ("Valid responses are 'no' and 'session'. Exiting.\n");
                        exit (1);
                }
                free (lineptr);
                break;
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
                printf ("Keep this privilege for the session or always? [no/session/always]?\n");
                getline (&lineptr, &linelen, stdin);
                if (g_str_has_prefix (lineptr, "no")) {
                        ;
                } else if (g_str_has_prefix (lineptr, "session")) {
                        keep_session = TRUE;
                } else if (g_str_has_prefix (lineptr, "always")) {
                        keep_always = TRUE;
                } else {
                        printf ("Valid responses are 'no', 'session' and 'always'. Exiting.\n");
                        exit (1);
                }
                free (lineptr);
                break;
        default:
                /* should never happen */
                exit (1);
        }

        switch (auth_type) {
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH:
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS:
                overridden_auth_type = POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH;
                if (keep_session)
                        overridden_auth_type = POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION;
                else if (keep_always)
                        overridden_auth_type = POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS;
                break;

        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION:
        case POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS:
                overridden_auth_type = POLKIT_RESULT_ONLY_VIA_SELF_AUTH;
                if (keep_session)
                        overridden_auth_type = POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION;
                else if (keep_always)
                        overridden_auth_type = POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS;
                break;

        default:
                /* should never happen */
                exit (1);
        }

        return overridden_auth_type;
}

static void 
conversation_done (PolKitGrant *polkit_grant, polkit_bool_t gained_privilege, polkit_bool_t invalid_data, void *user_data)
{
        UserData *ud = user_data;
        ud->gained_privilege = gained_privilege;
        g_main_loop_quit (ud->loop);
}




static void
child_watch_func (GPid pid,
                  gint status,
                  gpointer user_data)
{
        PolKitGrant *polkit_grant = user_data;
        polkit_grant_child_func (polkit_grant, pid, WEXITSTATUS (status));
}

static int
add_child_watch (PolKitGrant *polkit_grant, pid_t pid)
{
        return g_child_watch_add (pid, child_watch_func, polkit_grant);
}

static gboolean
io_watch_have_data (GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
        int fd;
        PolKitGrant *polkit_grant = user_data;
        fd = g_io_channel_unix_get_fd (channel);
        polkit_grant_io_func (polkit_grant, fd);
        return TRUE;
}

static int
add_io_watch (PolKitGrant *polkit_grant, int fd)
{
        guint id = 0;
        GIOChannel *channel;
        channel = g_io_channel_unix_new (fd);
        if (channel == NULL)
                goto out;
        id = g_io_add_watch (channel, G_IO_IN, io_watch_have_data, polkit_grant);
        if (id == 0) {
                g_io_channel_unref (channel);
                goto out;
        }
        g_io_channel_unref (channel);
out:
        return id;
}

static void 
remove_watch (PolKitGrant *polkit_auth, int watch_id)
{
        g_source_remove (watch_id);
}

static void
_print_grants (const char *action_id, 
               uid_t uid,
               time_t when, 
               PolKitGrantDbGrantType grant_type,
               pid_t pid,
               polkit_uint64_t pid_time,
               const char *session_id,
               void *user_data)
{
        char *user;
        char *when_str;
        struct passwd *passwd;

        passwd = getpwuid (uid);
        if (passwd != NULL)
                user = passwd->pw_name;
        else
                user = "NON_EXISTING_USER";

        when_str = ctime (&when);

        switch (grant_type) {
        case POLKIT_GRANTDB_GRANT_TYPE_PROCESS:
                printf ("process:\n"
                        "  user:    %s (uid %d)\n"
                        "  pid:     %d@%lld\n"
                        "  action:  %s\n"
                        "  granted: %s\n", 
                        user, uid, pid, pid_time, action_id, when_str);
                break;
        case POLKIT_GRANTDB_GRANT_TYPE_SESSION:
                printf ("session:\n"
                        "  user:    %s (uid %d)\n"
                        "  session: %s\n"
                        "  action:  %s\n"
                        "  granted: %s\n", 
                        user, uid, session_id, action_id, when_str);
                break;
        case POLKIT_GRANTDB_GRANT_TYPE_ALWAYS:
                printf ("always:\n"
                        "  user:    %s (uid %d)\n"
                        "  action:  %s\n"
                        "  granted: %s\n", 
                        user, uid, action_id, when_str);
                break;
        default:
                break;
        }
}


int
main (int argc, char *argv[])
{
        char *gain_action_id;
        gboolean is_version;
        DBusConnection *bus;
	DBusError error;
        PolKitContext *pol_ctx;
        PolKitCaller *caller;
        PolKitAction *action;
        PolKitError *p_error;
        PolKitGrant *polkit_grant;
        int ret;
        UserData ud;
        polkit_bool_t list_grants;
        char *delete_for_user;

        ret = 1;

	if (argc <= 1) {
		usage (argc, argv);
                goto out;
	}

        list_grants = FALSE;
        delete_for_user = NULL;
        is_version = FALSE;
        gain_action_id = NULL;
	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
                        {"list", 0, NULL, 0},
                        {"delete", 1, NULL, 0},
			{"gain", 1, NULL, 0},
			{"version", 0, NULL, 0},
			{"help", 0, NULL, 0},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			opt = long_options[option_index].name;

			if (strcmp (opt, "help") == 0) {
				usage (argc, argv);
				return 0;
			} else if (strcmp (opt, "version") == 0) {
				is_version = TRUE;
			} else if (strcmp (opt, "gain") == 0) {
				gain_action_id = strdup (optarg);
			} else if (strcmp (opt, "list") == 0) {
                                list_grants = TRUE;
			} else if (strcmp (opt, "delete") == 0) {
                                delete_for_user = strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
                        goto out;
		}
	}

	if (is_version) {
		printf ("polkit-grant " PACKAGE_VERSION "\n");
                ret = 0;
                goto out;
	}

        if (gain_action_id != NULL) {
                printf ("Attempting to gain the privilege for %s.\n", gain_action_id);
                
                ud.loop = g_main_loop_new (NULL, TRUE);
                
                dbus_error_init (&error);
                bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
                if (bus == NULL) {
                        fprintf (stderr, "error: dbus_bus_get(): %s: %s\n", error.name, error.message);
                        goto out;
                }
                
                p_error = NULL;
                pol_ctx = polkit_context_new ();
                if (!polkit_context_init (pol_ctx, &p_error)) {
                        fprintf (stderr, "error: polkit_context_init: %s\n", polkit_error_get_error_message (p_error));
                        polkit_error_free (p_error);
                        goto out;
                }
                
                action = polkit_action_new ();
                polkit_action_set_action_id (action, gain_action_id);
                
                caller = polkit_caller_new_from_dbus_name (bus, dbus_bus_get_unique_name (bus), &error);
                if (caller == NULL) {
                        if (dbus_error_is_set (&error)) {
                                fprintf (stderr, "error: polkit_caller_new_from_dbus_name(): %s: %s\n", 
                                         error.name, error.message);
                                goto out;
                        }
                }
                
                polkit_grant = polkit_grant_new ();
                polkit_grant_set_functions (polkit_grant,
                                            add_io_watch,
                                            add_child_watch,
                                            remove_watch,
                                            conversation_type,
                                            conversation_select_admin_user,
                                            conversation_pam_prompt_echo_off,
                                            conversation_pam_prompt_echo_on,
                                            conversation_pam_error_msg,
                                            conversation_pam_text_info,
                                            conversation_override_grant_type,
                                            conversation_done,
                                            &ud);
                
                if (!polkit_grant_initiate_auth (polkit_grant,
                                                 action,
                                                 caller)) {
                        printf ("Failed to initiate privilege grant.\n");
                        ret = 1;
                        goto out;
                }
                g_main_loop_run (ud.loop);
                polkit_grant_unref (polkit_grant);
                
                if (ud.gained_privilege)
                        printf ("Successfully gained the privilege for %s.\n", gain_action_id);
                else
                        printf ("Failed to gain the privilege for %s.\n", gain_action_id);
                
                ret = ud.gained_privilege ? 0 : 1;
        } else if (list_grants) {
                _polkit_grantdb_foreach (_print_grants, NULL);
                ret = 0;
        } else if (delete_for_user != NULL) {
                struct passwd *passwd;
                passwd = getpwnam (delete_for_user);
                if (passwd == NULL) {
                        printf ("No such user '%s'.\n", delete_for_user);
                        goto out;
                }
                if (!_polkit_grantdb_delete_for_user (passwd->pw_uid)) {
                        printf ("Error deleting grants for user '%s'. Got root?\n", delete_for_user);
                }
        } else {
		usage (argc, argv);
        }

out:
        return ret;
}

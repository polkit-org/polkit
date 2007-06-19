/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-check-session.c : check if a session is privileged
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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <polkit-dbus/polkit-dbus.h>

#include <glib.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : polkit-check-session\n"
                 "          [--session <session>] --action <action>\n"
                 "          [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --session        ConsoleKit object path of session\n"
                 "        --action         Requested action\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "Determine if a given callers in a given session can do a given action.\n"
                 "If no session is given, the current session is used. If access is\n"
                 "allowed, this program exits with exit code 0. If no access is allowed\n"
                 "or an error occurs, the program exits with a non-zero exit code.\n");
}

int
main (int argc, char *argv[])
{
        char *action_id = NULL;
        char *session_id = NULL;
        char *cookie = NULL;
        gboolean is_version = FALSE;
        DBusConnection *bus;
	DBusError error;
        PolKitContext *pol_ctx;
        PolKitSession *session;
        PolKitAction *action;
        gboolean allowed;
        PolKitError *p_error;

	if (argc <= 1) {
		usage (argc, argv);
		return 1;
	}

        cookie = getenv ("XDG_SESSION_COOKIE");

	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"action", 1, NULL, 0},
			{"session", 1, NULL, 0},
			{"version", 0, NULL, 0},
			{"help", 0, NULL, 0},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc, argv, "",
				 long_options, &option_index);
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
			} else if (strcmp (opt, "action") == 0) {
				action_id = strdup (optarg);
			} else if (strcmp (opt, "session") == 0) {
				session_id = strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
			return 1;
			break;
		}
	}

	if (is_version) {
		printf ("polkit-check-session " PACKAGE_VERSION "\n");
		return 0;
	}

	if (action_id == NULL) {
		usage (argc, argv);
		return 1;
	}

        dbus_error_init (&error);
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
		fprintf (stderr, "error: dbus_bus_get(): %s: %s\n", error.name, error.message);
		return 1;
	}

        p_error = NULL;
        pol_ctx = polkit_context_new ();
        if (!polkit_context_init (pol_ctx, &p_error)) {
		fprintf (stderr, "error: polkit_context_init: %s\n", polkit_error_get_error_message (p_error));
                polkit_error_free (p_error);
                return 1;
        }

        if (session_id != NULL) {
                session = polkit_session_new_from_objpath (bus, session_id, -1, &error);
        } else {
                if (cookie == NULL) {
                        fprintf (stderr, "Not part of a session. Try --session instead.\n");
                        return 1;
                }
                session = polkit_session_new_from_cookie (bus, cookie, &error);
        }
        if (session == NULL) {
		fprintf (stderr, "error: polkit_session_new_from_objpath: %s: %s\n", error.name, error.message);
		return 1;
        }

        action = polkit_action_new ();
        polkit_action_set_action_id (action, action_id);

        allowed = polkit_context_can_session_do_action (pol_ctx, action, session);

        if (allowed)
                return 0;
        else
                return 1;
}

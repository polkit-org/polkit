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

#include <libpolkit/libpolkit.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : polkit-check-session\n"
                 "          [--session <session>] --action <action>\n"
                 "          [--action-param <key>=<value>]"
                 "          --resource-type <type> --resource-id <id>\n"
                 "          [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --session        ConsoleKit object path of session\n"
                 "        --action         Requested action\n"
                 "        --action-param   Action parameters (may occur multiple times)\n"
                 "        --resource-type  Type of resource\n"
                 "        --resource-id    Identifier of resource\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "Determine if a given session can access a given resource in a given\n"
                 "way. If no session is given, the current session is used. If access\n"
                 "is allowed, this program exits with exit code 0. If no access is allowed\n"
                 "or an error occurs, the program exits with a non-zero exit code.\n");
}

int
main (int argc, char *argv[])
{
        char *resource_type = NULL;
        char *resource_id = NULL;
        char *action_id = NULL;
        char *session_id = NULL;
        char *cookie = NULL;
        gboolean is_version = FALSE;
        DBusConnection *bus;
	DBusError error;
        PolKitContext *pol_ctx;
        PolKitSession *session;
        PolKitResource *resource;
        PolKitAction *action;
        gboolean allowed;
        GError *g_error;
        GPtrArray *params;
        int n;
        char *param_key;
        char *param_value;

	if (argc <= 1) {
		usage (argc, argv);
		return 1;
	}

        cookie = getenv ("XDG_SESSION_COOKIE");

        params = g_ptr_array_new ();
	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"resource-type", 1, NULL, 0},
			{"resource-id", 1, NULL, 0},
			{"action", 1, NULL, 0},
			{"action-param", 1, NULL, 0},
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
			} else if (strcmp (opt, "resource-type") == 0) {
				resource_type = strdup (optarg);
			} else if (strcmp (opt, "resource-id") == 0) {
				resource_id = strdup (optarg);
			} else if (strcmp (opt, "action") == 0) {
				action_id = strdup (optarg);
			} else if (strcmp (opt, "action-param") == 0) {
				param_key = strdup (optarg);
                                param_value = NULL;
                                for (n = 0; param_key[n] != '=' && param_key[n] != '\0'; n++)
                                        ;
                                if (param_key[n] == '\0')
                                        usage (argc, argv);
                                param_key[n] = '\0';
                                param_value = param_key + n + 1;
                                g_ptr_array_add (params, g_strdup (param_key));
                                g_ptr_array_add (params, g_strdup (param_value));
                                g_free (param_key);
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

	if (resource_type == NULL || resource_id == NULL || action_id == NULL) {
		usage (argc, argv);
		return 1;
	}

        dbus_error_init (&error);
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
		fprintf (stderr, "error: dbus_bus_get(): %s: %s\n", error.name, error.message);
		return 1;
	}

        g_error = NULL;
        pol_ctx = libpolkit_context_new ();
        if (!libpolkit_context_init (pol_ctx, &g_error)) {
		fprintf (stderr, "error: libpolkit_context_init: %s\n", g_error->message);
                g_error_free (g_error);
                return 1;
        }

        if (session_id != NULL) {
                session = libpolkit_session_new_from_objpath (bus, session_id, -1, &error);
        } else {
                if (cookie == NULL) {
                        fprintf (stderr, "Not part of a session. Try --session instead.\n");
                        return 1;
                }
                session = libpolkit_session_new_from_cookie (bus, cookie, &error);
        }
        if (session == NULL) {
		fprintf (stderr, "error: libpolkit_session_new_from_objpath: %s: %s\n", error.name, error.message);
		return 1;
        }

        action = libpolkit_action_new ();
        libpolkit_action_set_action_id (action, action_id);
        for (n = 0; n < (int) params->len; n += 2) {
                char *key;
                char *value;
                key = params->pdata[n];
                value = params->pdata[n+1];
                libpolkit_action_set_param (action, key, value);
                g_free (key);
                g_free (value);
        }
        g_ptr_array_free (params, TRUE);

        resource = libpolkit_resource_new ();
        libpolkit_resource_set_resource_type (resource, resource_type);
        libpolkit_resource_set_resource_id (resource, resource_id);

        allowed = libpolkit_context_can_session_access_resource (pol_ctx, action, resource, session);

        if (allowed)
                return 0;
        else
                return 1;
}

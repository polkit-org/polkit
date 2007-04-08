/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-check-caller.c : check if a caller is privileged
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
                 "usage : polkit-check-caller\n"
                 "          --resource-type <type> --resource-id <id>\n"
                 "          --privilege <privilege> --caller <dbus-name>\n"
                 "          [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --resource-type  Type of resource\n"
                 "        --resource-id    Identifier of resource\n"
                 "        --privilege      Requested privilege\n"
                 "        --caller         Unique name of caller on the system bus\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "Determine if a given caller can access a given resource in a given\n"
                 "way. If access is allowed, this program exits with exit code 0. If\n"
                 "no access is allowed or an error occurs, the program exits with\n"
                 "a non-zero exit code.\n");
}

int
main (int argc, char *argv[])
{
        char *resource_type = NULL;
        char *resource_id = NULL;
        char *privilege_id = NULL;
        char *dbus_name = NULL;
        gboolean is_version = FALSE;
        DBusConnection *bus;
	DBusError error;
        PolKitContext *pol_ctx;
        PolKitCaller *caller;
        PolKitResource *resource;
        PolKitPrivilege *privilege;
        gboolean allowed;
        GError *g_error;

	if (argc <= 1) {
		usage (argc, argv);
		return 1;
	}

	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"resource-type", 1, NULL, 0},
			{"resource-id", 1, NULL, 0},
			{"privilege", 1, NULL, 0},
			{"caller", 1, NULL, 0},
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
			} else if (strcmp (opt, "privilege") == 0) {
				privilege_id = strdup (optarg);
			} else if (strcmp (opt, "caller") == 0) {
				dbus_name = strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
			return 1;
			break;
		}
	}

	if (is_version) {
		printf ("polkit-check-caller " PACKAGE_VERSION "\n");
		return 0;
	}

	if (resource_type == NULL || resource_id == NULL || privilege_id == NULL || dbus_name == NULL) {
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

        privilege = libpolkit_privilege_new ();
        libpolkit_privilege_set_privilege_id (privilege, privilege_id);

        resource = libpolkit_resource_new ();
        libpolkit_resource_set_resource_type (resource, resource_type);
        libpolkit_resource_set_resource_id (resource, resource_id);

        caller = libpolkit_caller_new_from_dbus_name (bus, dbus_name, &error);
        if (caller == NULL) {
                if (dbus_error_is_set (&error)) {
                        fprintf (stderr, "error: libpolkit_caller_new_from_dbus_name(): %s: %s\n", 
                                 error.name, error.message);
                        return 1;
                }
        }

        allowed = libpolkit_context_can_caller_access_resource (pol_ctx, privilege, resource, caller);

        if (allowed)
                return 0;
        else
                return 1;
}

/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-list-privileges.c : List privileges possesed by a user
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <dbus/dbus.h>

#include <libpolkit/libpolkit.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr, "polkit-list-privileges version " PACKAGE_VERSION "\n");

	fprintf (stderr, "\n" "usage : %s [-u <user>]\n", argv[0]);
	fprintf (stderr,
		 "\n"
		 "Options:\n"
		 "    -u, --user           Username or user id\n"
		 "    -h, --help           Show this information and exit\n"
		 "    -v, --verbose        Verbose operation\n"
		 "    -V, --version        Print version number\n"
		 "\n"
		 "Lists privileges for a given user.\n"
		 "\n");
}

int 
main (int argc, char *argv[])
{
	int rc;
	char *user = NULL;
	static const struct option long_options[] = {
		{"user", required_argument, NULL, 'u'},
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};
	LibPolKitContext *ctx = NULL;
	gboolean is_verbose = FALSE;
	DBusError error;
	DBusConnection *connection;
	int i;
	GList *l;
	GList *privilege_list;

	rc = 1;
	
	while (TRUE) {
		int c;
		
		c = getopt_long (argc, argv, "u:p:hVv", long_options, NULL);

		if (c == -1)
			break;
		
		switch (c) {
		case 'u':
			user = g_strdup (optarg);
			break;
			
		case 'v':
			is_verbose = TRUE;
			break;

		case 'h':
			usage (argc, argv);
			rc = 0;
			goto out;

		case 'V':
			printf ("polkit-list-privileges version " PACKAGE_VERSION "\n");
			rc = 0;
			goto out;
			
		default:
			usage (argc, argv);
			goto out;
		}
	}

	if (user == NULL) {
		user = g_strdup (g_get_user_name ());
	}

	if (is_verbose) {
		printf ("user     = '%s'\n", user);
	}

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		g_warning ("Cannot connect to system message bus");
		return 1;
	}


	ctx = libpolkit_new_context (connection);
	if (ctx == NULL) {
		g_warning ("Cannot get libpolkit context");
		goto out;
	}

	if (libpolkit_get_privilege_list (ctx, &privilege_list) != LIBPOLKIT_RESULT_OK) {
		g_warning ("Cannot get privilege_list");
		goto out;
	}
	for (l = privilege_list, i = 0; l != NULL; l = g_list_next (l), i++) {
		const char *privilege;
		gboolean is_allowed;
		GList *j;
		GList *resources;

		privilege = (const char *) l->data;
		if (is_verbose) {
			g_print ("testing user %s for privilege '%s'\n", user, privilege);
		}

		if (libpolkit_is_uid_allowed_for_privilege (ctx, 
							    -1,
							    user,
							    privilege,
							    NULL,
							    &is_allowed) == LIBPOLKIT_RESULT_OK) {
			if (is_allowed) {
				g_print ("privilege %s\n", privilege);
			} else {
				if (libpolkit_get_allowed_resources_for_privilege_for_uid (ctx, 
											   user,
											   privilege,
											   &resources) == LIBPOLKIT_RESULT_OK) {
					for (j = resources; j != NULL; j = g_list_next (j)) {
						const char *resource;
						resource = (const char *) j->data;
						g_print ("resource %s privilege %s\n", resource, privilege);
					}
					g_list_foreach (resources, (GFunc) g_free, NULL);
					g_list_free (resources);
				}
			}
		}



	}
	g_list_foreach (privilege_list, (GFunc) g_free, NULL);
	g_list_free (privilege_list);

	rc = 0;

out:
	if (ctx != NULL)
		libpolkit_free_context (ctx);

	return rc;
}

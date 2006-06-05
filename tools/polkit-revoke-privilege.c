/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-grant-privilege.c : Grant privileges
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

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>

#include <glib/gstdio.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <libpolkit/libpolkit.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr, "polkit-revoke-privilege version " PACKAGE_VERSION "\n");

	fprintf (stderr, "\n" "usage : %s -p <privilege> [-u user] [-r <resource>]\n", argv[0]);
	fprintf (stderr,
		 "\n"
		 "Options:\n"
		 "    -u, --user           User to revoke privilege from\n"
		 "    -p, --privilege      Privilege to revoke\n"
		 "    -r, --resource       Resource\n"
		 "    -h, --help           Show this information and exit\n"
		 "    -v, --verbose        Verbose operation\n"
		 "    -V, --version        Print version number\n"
		 "\n"
		 "Revokes a privilege for accessing a resource. The resource may\n"
		 "be omitted.\n");
}

static gboolean is_verbose = FALSE;

int
main (int argc, char **argv)
{
	int rc;
	GError *error = NULL;
	DBusGConnection *bus;
	LibPolKitContext *ctx;
	char *user = NULL;
	char *resource = NULL;
	char *privilege = NULL;
	static const struct option long_options[] = {
		{"user", required_argument, NULL, 'u'},
		{"resource", required_argument, NULL, 'r'},
		{"privilege", required_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};
	gboolean was_revoked;

	g_type_init ();

	rc = 1;

	while (TRUE) {
		int c;
		
		c = getopt_long (argc, argv, "u:r:p:hVv", long_options, NULL);

		if (c == -1)
			break;
		
		switch (c) {
		case 'u':
			user = g_strdup (optarg);
			break;

		case 'r':
			resource = g_strdup (optarg);
			break;

		case 'p':
			privilege = g_strdup (optarg);
			break;
			
		case 'v':
			is_verbose = TRUE;
			break;

		case 'h':
			usage (argc, argv);
			rc = 0;
			goto out;

		case 'V':
			printf ("polkit-grant-privilege version " PACKAGE_VERSION "\n");
			rc = 0;
			goto out;
			
		default:
			usage (argc, argv);
			goto out;
		}
	}

	if (privilege == NULL) {
		usage (argc, argv);
		return 1;
	}

	if (user == NULL) {
		user = g_strdup (g_get_user_name ());
	}

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (bus == NULL) {
		g_warning ("dbus_g_bus_get: %s", error->message);
		g_error_free (error);
		return 1;
	}

	ctx = libpolkit_new_context (dbus_g_connection_get_connection (bus));

	LibPolKitResult result;

	result = libpolkit_revoke_temporary_privilege (ctx,
						       user,
						       privilege,
						       resource,
						       &was_revoked);
	switch (result) {
	case LIBPOLKIT_RESULT_OK:
		if (was_revoked) {
			if (resource == NULL) {
				g_print ("Privilege '%s' succesfully revoked from user '%s'.\n", privilege, user);
			} else {
				g_print ("Privilege '%s' succesfully revoked from user '%s' on\n"
					 "resource '%s'.\n", 
					 privilege, user, resource);
			}
			rc = 0;
			goto out;
		}
		break;

	case LIBPOLKIT_RESULT_ERROR:
		g_print ("Error: There was an error granting the privilege.\n");
		goto out;

	case LIBPOLKIT_RESULT_INVALID_CONTEXT:
		g_print ("Error: Invalid context.\n");
		goto out;

	case LIBPOLKIT_RESULT_NOT_PRIVILEGED:
		g_print ("Error: Not privileged to perform this operation.\n");
		goto out;

	case LIBPOLKIT_RESULT_NO_SUCH_PRIVILEGE:
		if (resource == NULL) {
			g_print ("Error: User '%s' does not have privilege '%s'.\n", user, privilege);
		} else {
			g_print ("Error: User '%s' does not have privilege '%s' for accessing\n"
				 "resource '%s'.\n", 
				 user, privilege, resource);
		}
		goto out;

	case LIBPOLKIT_RESULT_NO_SUCH_USER:
		g_print ("Error: No such user '%s'.\n", user);
		goto out;
	}

	
out:
	return rc;
}

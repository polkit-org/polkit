/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-is-privileged.c : Small command line wrapper for libpolkit
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
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

#include <libpolkit/libpolkit.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr, "polkit-is-privileged version " PACKAGE_VERSION "\n");

	fprintf (stderr, "\n" "usage : %s -u <uid> -p <policy> [-r <resource>]\n", argv[0]);
	fprintf (stderr,
		 "\n"
		 "Options:\n"
		 "    -u, --uid            Username or user id\n"
		 "    -r, --resource       Resource\n"
		 "    -p, --policy         policy to test for\n"
		 "    -h, --help           Show this information and exit\n"
		 "    -v, --verbose        Verbose operation\n"
		 "    -V, --version        Print version number\n"
		 "\n"
		 "Queries system policy whether a given user is allowed for a given\n"
		 "policy for a given resource. The resource may be omitted.\n"
		 "\n"
		 "System policies are defined in the " PACKAGE_SYSCONF_DIR "/PolicyKit/policy directory.\n"
		 "\n");
}

int 
main (int argc, char *argv[])
{
	int rc;
	uid_t uid;
	char *user = NULL;
	char *policy = NULL;
	char *resource = NULL;
	static const struct option long_options[] = {
		{"uid", required_argument, NULL, 'u'},
		{"resource", required_argument, NULL, 'r'},
		{"policy", required_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};
	LibPolKitContext *ctx = NULL;
	char *endp;
	gboolean is_allowed;
	LibPolKitResult result;
	gboolean is_verbose = FALSE;

	rc = 1;
	
	while (TRUE) {
		int c;
		
		c = getopt_long (argc, argv, "u:r:p:UhVv", long_options, NULL);

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
			policy = g_strdup (optarg);
			break;
			
		case 'v':
			is_verbose = TRUE;
			break;

		case 'h':
			usage (argc, argv);
			rc = 0;
			goto out;

		case 'V':
			printf ("polkit-is-privileged version " PACKAGE_VERSION "\n");
			rc = 0;
			goto out;
			
		default:
			usage (argc, argv);
			goto out;
		}
	}

	if (user == NULL || policy == NULL) {
		usage (argc, argv);
		return 1;
	}

	if (is_verbose) {
		printf ("user     = '%s'\n", user);
		printf ("policy   = '%s'\n", policy);
		printf ("resource = '%s'\n", resource);
	}

	ctx = libpolkit_new_context ();
	if (ctx == NULL) {
		g_warning ("Cannot get policy context");
		goto out;
	}

	uid = (uid_t) g_ascii_strtoull (user, &endp, 0);
	if (endp[0] != '\0') {
		uid = libpolkit_util_name_to_uid (ctx, user, NULL);
		if (uid == (uid_t) -1) {
			g_warning ("User '%s' does not exist", user);
			goto out;
		}
	}

	if (is_verbose) {
		printf ("user '%s' is uid %d\n", user, (int) uid);
	}

	result = libpolkit_is_uid_allowed_for_policy (ctx, 
							  uid,
							  policy,
							  resource,
							  &is_allowed);
	switch (result) {
	case LIBPOLKIT_RESULT_OK:
		rc = is_allowed ? 0 : 1;
		break;

	case LIBPOLKIT_RESULT_ERROR:
		g_warning ("error retrieving policy");
		break;

	case LIBPOLKIT_RESULT_INVALID_CONTEXT:
		g_warning ("invalid context");
		break;

	case LIBPOLKIT_RESULT_PERMISSON_DENIED:
		g_warning ("permission denied");
		break;

	case LIBPOLKIT_RESULT_NO_SUCH_POLICY:
		g_warning ("no such policy '%s'", policy);
		break;
	}

	if (is_verbose) {
		printf ("result %d\n", result);
		printf ("is_allowed %d\n", is_allowed);
	}

out:
	if (ctx != NULL)
		libpolkit_free_context (ctx);

	return rc;
}


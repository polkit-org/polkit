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
#include <libpolkit/libpolkit-grant.h>


static gboolean is_verbose = FALSE;


static void
questions_cb (LibPolKitGrantContext  *ctx, 
	      const char            **questions,
	      gpointer                user_data)
{
	int i;
	int num_a;
	char **answers;
	static gboolean showed_user = FALSE;


	/* print banner for user if we are going to ask questions */
	if (!showed_user) {
		const char *auth_user;
		const char *auth_pam_svc;

		showed_user = TRUE;

		auth_user = libpolkit_grant_get_user_for_auth (ctx);
		auth_pam_svc = libpolkit_grant_get_pam_service_for_auth (ctx);

		if (libpolkit_grant_get_resource (ctx) != NULL) {
			g_print ("\n"
				 "Authentication needed for user '%s' in order to grant the\n"
				 "privilege '%s' to user '%s' for the \n"
				 "resource '%s'.\n"
				 "\n"
				 "The privilege is configured to use PAM service '%s'.\n"
				 "\n",
				 auth_user,
				 libpolkit_grant_get_privilege (ctx), 
				 libpolkit_grant_get_user (ctx), 
				 libpolkit_grant_get_resource (ctx),
				 auth_pam_svc);
		} else {
			g_print ("\n"
				 "Authentication needed for user '%s' in order to grant the\n"
				 "privilege '%s' to user '%s'.\n"
				 "\n"
				 "The privilege is configured to use PAM service '%s'.\n"
				 "\n",
				 auth_user,
				 libpolkit_grant_get_privilege (ctx), 
				 libpolkit_grant_get_user (ctx),
				 auth_pam_svc);
		}
	}


	answers = g_new0 (char *, g_strv_length ((char **) questions) + 1);
	num_a = 0;

	for (i = 0; questions[i] != NULL && questions[i+1] != NULL; i++) {
		char *answer;
		const char *question = questions[i+1];
		const char *qtype = questions[i];

		/*g_debug ("Question 1: '%s' (pamtype %s)\n(warning; secret will be echoed to stdout)", question, qtype);*/

		if (strcmp (qtype, "PamPromptEchoOff") == 0) {
			answer = getpass (question);
			answers[num_a++] = g_strdup (answer);

			/*g_debug ("Provding answer: '%s'", answer);*/

		} else if (strcmp (qtype, "PamPromptEchoOn") == 0) {
			char buf[1024];

			fputs (question, stderr);
			answer = fgets ((char *) question, sizeof (buf), stdin);
			answers[num_a++] = g_strdup (answer);

			/*g_debug ("Provding answer: '%s'", answer);*/

		} else if (strcmp (qtype, "PamErrorMsg") == 0) {
			/*g_debug ("Not providing answer");*/
			;
		} else if (strcmp (qtype, "PamTextInfo") == 0) {
			/*g_debug ("Not providing answer");*/
			;
		} 
	}
	answers[num_a] = NULL;

	libpolkit_grant_provide_answers (ctx, (const char **) answers);

	g_strfreev (answers);
}

static void
grant_complete_cb (LibPolKitGrantContext  *ctx, 
		   gboolean                obtained_privilege,
		   const char             *reason_not_obtained,
		   gpointer                user_data)
{
	if (!obtained_privilege) {
		g_print ("Privilege not granted: %s\n", reason_not_obtained != NULL ? reason_not_obtained : "(null)");
	} else {
		/* keep the privilege */
		libpolkit_grant_close (ctx, FALSE);
	}

	libpolkit_free_context (ctx);

	exit (0);
}



static void
usage (int argc, char *argv[])
{
	fprintf (stderr, "polkit-grant-privilege version " PACKAGE_VERSION "\n");

	fprintf (stderr, "\n" "usage : %s -p <privilege> [-u user] [-r <resource>]\n", argv[0]);
	fprintf (stderr,
		 "\n"
		 "Options:\n"
		 "    -u, --user           User to grant privilege to\n"
		 "    -p, --privilege      Privilege to grant\n"
		 "    -r, --resource       Resource\n"
		 "    -h, --help           Show this information and exit\n"
		 "    -v, --verbose        Verbose operation\n"
		 "    -V, --version        Print version number\n"
		 "\n"
		 "Grant a privilege for accessing a resource. The resource may\n"
		 "be omitted.\n");
}

int
main (int argc, char **argv)
{
	int rc;
	GError *error = NULL;
	DBusGConnection *bus;
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
	gboolean is_privileged = FALSE;
	gboolean is_temporary = FALSE;
	LibPolKitResult result;
	LibPolKitGrantContext *gctx;
	LibPolKitContext *ctx;
	GMainLoop *mainloop;

	g_type_init ();

	mainloop = g_main_loop_new (NULL, FALSE);


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

	gctx = libpolkit_grant_new_context (bus,
					    user,
					    privilege,
					    resource,
					    FALSE,
					    NULL);
	if (gctx == NULL) {
		g_warning ("Cannot initialize new grant context");
		goto out;
	}

	ctx = libpolkit_grant_get_libpolkit_context (gctx);
	result = libpolkit_is_uid_allowed_for_privilege (ctx,
							 NULL,
							 user,
							 privilege,
							 resource,
							 &is_privileged,
							 &is_temporary,
							 NULL);
	switch (result) {
	case LIBPOLKIT_RESULT_OK:
		if (is_privileged) {
			if (resource == NULL) {
				g_print ("User '%s' already has privilege '%s'.\n", user, privilege);
			} else {
				g_print ("User '%s' already has privilege '%s' for accessing\n"
					 "resource '%s'.\n", 
					 user, privilege, resource);
			}
			rc = 0;
			goto out;
		}
		break;

	case LIBPOLKIT_RESULT_ERROR:
		g_print ("Error granting resource.\n");
		goto out;

	case LIBPOLKIT_RESULT_INVALID_CONTEXT:
		g_print ("Invalid context.\n");
		goto out;

	case LIBPOLKIT_RESULT_NOT_PRIVILEGED:
		g_print ("Not privileged.\n");
		goto out;

	case LIBPOLKIT_RESULT_NO_SUCH_PRIVILEGE:
		g_print ("No such privilege '%s'.\n", privilege);
		goto out;

	case LIBPOLKIT_RESULT_NO_SUCH_USER:
		g_print ("No such user '%s'.\n", user);
		goto out;
	}

	libpolkit_grant_set_questions_handler (gctx, questions_cb);
	libpolkit_grant_set_grant_complete_handler (gctx, grant_complete_cb);

	if (!libpolkit_grant_initiate_temporary_grant (gctx)) {
		g_warning ("Cannot initiate temporary grant; bailing out");
		goto out;
	}

	g_main_loop_run (mainloop);

out:
	return rc;
}

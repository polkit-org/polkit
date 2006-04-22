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

#include "polkit-interface-manager-glue.h"
#include "polkit-interface-session-glue.h"

static char *grant_user = NULL;
static char *grant_privilege = NULL;
static char *grant_resource = NULL;
static char *auth_user = NULL;
static char *auth_pam_service_name = NULL;

static void
have_questions_handler (DBusGProxy *session, gpointer user_data)
{
	int i;
	char **questions;
	char **answers;
	int num_a;
	GError *error = NULL;

	if (auth_user != NULL) {
		if (grant_resource != NULL)
			g_print ("\n"
				 "Authentication needed for user '%s' in order to grant the\n"
				 "privilege '%s' to user '%s' for the \n"
				 "resource '%s'.\n"
				 "\n"
				 "The privilege is configured to use PAM service '%s'.\n"
				 "\n",
				 auth_user,
				 grant_privilege, grant_user, 
				 grant_resource,
				 auth_pam_service_name);
		else
			g_print ("\n"
				 "Authentication needed for user '%s' in order to grant the\n"
				 "privilege '%s' to user '%s'.\n"
				 "\n"
				 "The privilege is configured to use PAM service '%s'.\n"
				 "\n",
				 auth_user,
				 grant_privilege, grant_user,
				 auth_pam_service_name);
		g_free (auth_user);
		g_free (auth_pam_service_name);
		auth_user = NULL;
		auth_pam_service_name = NULL;
	}

	if (!org_freedesktop_PolicyKit_Session_get_questions (session,
							      &questions,
							      &error)) {
		g_warning ("GetQuestions: %s", error->message);
		g_error_free (error);
		goto out;
	}

	answers = g_new0 (char *, g_strv_length (questions) + 1);
	num_a = 0;

	for (i = 0; questions[i] != NULL && questions[i+1] != NULL; i++) {
		char *answer;
		char *question = questions[i+1];
		char *qtype = questions[i];

		/*g_debug ("Question 1: '%s' (pamtype %s)\n(warning; secret will be echoed to stdout)", question, qtype);*/

		if (strcmp (qtype, "PamPromptEchoOff") == 0) {
			answer = getpass (question);
			answers[num_a++] = g_strdup (answer);

			/*g_debug ("Provding answer: '%s'", answer);*/

		} else if (strcmp (qtype, "PamPromptEchoOn") == 0) {
			char buf[1024];

			fputs (question, stderr);
			answer = fgets (question, sizeof (buf), stdin);
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

	g_strfreev (questions);

	if (!org_freedesktop_PolicyKit_Session_provide_answers (session,
								(const char **) answers,
								&error)) {
		g_warning ("ProvideAnswers: %s", error->message);
		g_error_free (error);
		goto out;
	}

	g_strfreev (answers);

out:
	;
}

static void
auth_done_handler (DBusGProxy *session, gpointer user_data)
{
	gboolean auth_result;
	GError *error = NULL;

	/*g_debug ("in %s", __FUNCTION__);*/

	if (!org_freedesktop_PolicyKit_Session_is_authenticated (session,
								 &auth_result,
								 &error)) {
		g_warning ("IsAuthenticated: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/*g_message ("Authentication done. %s", auth_result);*/

	if (!auth_result) {
		char *auth_denied_reason;

		if (!org_freedesktop_PolicyKit_Session_get_auth_denied_reason (session,
									       &auth_denied_reason,
									       &error)) {
			g_warning ("GetAuthDeniedReason: %s", error->message);
			g_error_free (error);
			goto out;
		}
		
		g_print ("\n"
			 "Authentication failed (reason: '%s').\n", auth_denied_reason);
		g_free (auth_denied_reason);
	} else {
		g_print ("\n"
			 "Authentication succeeded.\n");

		/* don't restrict privilege to callers PID */
		if (!org_freedesktop_PolicyKit_Session_grant_privilege_temporarily (session,
										    FALSE,
										    &error)) {
			g_warning ("GrantPrivilegeTemporarily: %s", error->message);
			g_error_free (error);
		}
	}

out:

	/* don't revoke privilege when we close the session */
	if (!org_freedesktop_PolicyKit_Session_close (session,
						      TRUE,
						      &error)) {
		g_warning ("Close: %s", error->message);
		g_error_free (error);
	}

	exit (0);
}

static void
do_grant_privilege (DBusGConnection *conn, const char *user, const char *privilege, const char *resource)
{
	GError *error = NULL;
	DBusGProxy *manager;
	DBusGProxy *session;
	char *session_objpath;
	GMainLoop *mainloop;

	grant_user = g_strdup (user);
	grant_privilege = g_strdup (privilege);
	grant_resource = g_strdup (resource);

	mainloop = g_main_loop_new (NULL, FALSE);

	manager = dbus_g_proxy_new_for_name (conn,
					     "org.freedesktop.PolicyKit",
					     "/org/freedesktop/PolicyKit/Manager",
					     "org.freedesktop.PolicyKit.Manager");
	if (manager == NULL) {
		goto out;
	}

	if (!org_freedesktop_PolicyKit_Manager_initiate_temporary_privilege_grant (manager,
										   user,
										   privilege,
										   resource,
										   &session_objpath,
										   &error)) {
		g_warning ("GrantPrivilege: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/*g_debug ("session_objpath = %s", session_objpath);*/

	session = dbus_g_proxy_new_for_name (conn,
					     "org.freedesktop.PolicyKit",
					     session_objpath,
					     "org.freedesktop.PolicyKit.Session");
	if (session == NULL) {
		goto out;
	}

	dbus_g_proxy_add_signal (session, "HaveQuestions", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (session, "HaveQuestions", G_CALLBACK (have_questions_handler),
				     NULL, NULL);

	dbus_g_proxy_add_signal (session, "AuthenticationDone", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (session, "AuthenticationDone", G_CALLBACK (auth_done_handler),
				     NULL, NULL);

	if (!org_freedesktop_PolicyKit_Session_get_auth_details (session,
								 &auth_user,
								 &auth_pam_service_name,
								 &error)) {
		g_warning ("GetAuthDetails: %s", error->message);
		g_error_free (error);
		goto out;
	}

	if (!org_freedesktop_PolicyKit_Session_initiate_auth (session,
							      &error)) {
		g_warning ("InitiateAuth: %s", error->message);
		g_error_free (error);
		goto out;
	}

	g_main_loop_run (mainloop);


	g_free (session_objpath);
out:
	;
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
	gboolean is_privileged = FALSE;
	gboolean is_temporary = FALSE;
	LibPolKitResult result;

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

	result = libpolkit_is_uid_allowed_for_privilege (ctx,
							 -1,
							 user,
							 privilege,
							 resource,
							 &is_privileged,
							 &is_temporary);
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

	do_grant_privilege (bus, user, privilege, resource);

out:
	return rc;
}

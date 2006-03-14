/***************************************************************************
 * CVSID: $Id$
 *
 * main.c : Main for polkitd
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
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dbus/dbus-glib.h>

#include "polkit-session.h"
#include "polkit-manager.h"

#include "polkit-interface-session-glue.h"
#include "polkit-interface-manager-glue.h"

/** Print out program usage.
 *
 */
static void
usage (int argc, char *argv[])
{
	fprintf (stderr, "\n" "usage : polkitd [--no-daemon] [--verbose]\n");
	fprintf (stderr,
		 "\n"
		 "        -n, --no-daemon      Do not daemonize\n"
		 "        -v, --verbose        Print out debug\n"
		 "        -h, --help           Show this information and exit\n"
		 "        -V, --version        Output version information and exit"
		 "\n"
		 "The PolicyKit daemon maintains a list of privileges and\n"
		 "provides interfaces for changing it.\n"
		 "\n"
		 "For more information visit http://freedesktop.org/Software/hal\n"
		 "\n");
}

static void 
delete_pid (void)
{
	unlink (POLKITD_PID_FILE);
}

int
main (int argc, char *argv[])
{
	DBusGConnection *bus;
	DBusGProxy *bus_proxy;
	GError *error = NULL;
	PolicyKitManager *manager;
	GMainLoop *mainloop;
	guint request_name_result;
	int ret;
	gboolean no_daemon = FALSE;
	gboolean is_verbose = FALSE;
	static const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"no-daemon", no_argument, NULL, 'n'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{NULL, 0, NULL, 0}
	};


	ret = 1;

	g_type_init ();

	while (TRUE) {
		int c;
		
		c = getopt_long (argc, argv, "nhVv", long_options, NULL);

		if (c == -1)
			break;
		
		switch (c) {
		case 'n':
			no_daemon = TRUE;
			break;

		case 'v':
			is_verbose = TRUE;
			break;

		case 'h':
			usage (argc, argv);
			ret = 0;
			goto out;

		case 'V':
			printf (PACKAGE_NAME " version " PACKAGE_VERSION "\n");
			ret = 0;
			goto out;
			
		default:
			usage (argc, argv);
			goto out;
		}
	}


	if (!no_daemon) {
		int child_pid;
		int dev_null_fd;
		int pf;
		ssize_t written;
		char pid[9];
		

		if (chdir ("/") < 0) {
			g_warning ("Could not chdir to /: %s", strerror (errno));
			goto out;
		}

		child_pid = fork ();
		switch (child_pid) {
		case -1:
			g_warning ("Cannot fork(): %s", strerror (errno));
			goto out;

		case 0:
			/* child */
			dev_null_fd = open ("/dev/null", O_RDWR);
			/* ignore if we can't open /dev/null */
			if (dev_null_fd >= 0) {
				/* attach /dev/null to stdout, stdin, stderr */
				dup2 (dev_null_fd, 0);
				dup2 (dev_null_fd, 1);
				dup2 (dev_null_fd, 2);
				close (dev_null_fd);
			}

			umask (022);
			break;

		default:
			/* parent exits */
			exit (0);
			break;
		}

		/* create session */
		setsid ();

		/* remove old pid file */
		unlink (POLKITD_PID_FILE);

		/* make a new pid file */
		if ((pf = open (POLKITD_PID_FILE, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644)) > 0) {
			snprintf (pid, sizeof(pid), "%lu\n", (long unsigned) getpid ());
			written = write (pf, pid, strlen(pid));
			close (pf);
			g_atexit (delete_pid);
		}
	} else {
		g_debug (("not becoming a daemon"));
	}

	g_type_init ();

	dbus_g_object_type_install_info (POLKIT_TYPE_MANAGER, &dbus_glib_polkit_manager_object_info);
	dbus_g_object_type_install_info (POLKIT_TYPE_SESSION, &dbus_glib_polkit_session_object_info);
	dbus_g_error_domain_register (POLKIT_MANAGER_ERROR, NULL, POLKIT_MANAGER_TYPE_ERROR);
	dbus_g_error_domain_register (POLKIT_SESSION_ERROR, NULL, POLKIT_SESSION_TYPE_ERROR);

	mainloop = g_main_loop_new (NULL, FALSE);

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (bus == NULL) {
		g_warning ("Couldn't connect to system bus: %s", error->message);
		g_error_free (error);
		goto out;
	}

	bus_proxy = dbus_g_proxy_new_for_name (bus, "org.freedesktop.DBus",
					       "/org/freedesktop/DBus",
					       "org.freedesktop.DBus");
	if (!dbus_g_proxy_call (bus_proxy, "RequestName", &error,
				G_TYPE_STRING, "org.freedesktop.PolicyKit",
				G_TYPE_UINT, 0,
				G_TYPE_INVALID,
				G_TYPE_UINT, &request_name_result,
				G_TYPE_INVALID)) {
		g_warning ("Failed to acquire org.freedesktop.PolicyKit: %s", error->message);
		g_error_free (error);
		goto out;
	}
	


	manager = polkit_manager_new (bus, bus_proxy);

	g_debug ("service running");

	g_main_loop_run (mainloop);

	ret = 0;
out:
	return ret;
}

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
#include <signal.h>

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

static int sigusr1_unix_signal_pipe_fds[2];
static GIOChannel *sigusr1_iochn = NULL;
static PolicyKitManager *manager = NULL;

static void 
handle_sigusr1 (int value)
{
	ssize_t written;
	static char marker[1] = {'S'};

	written = write (sigusr1_unix_signal_pipe_fds[1], marker, 1);
}

static gboolean
sigusr1_iochn_data (GIOChannel *source, 
		    GIOCondition condition, 
		    gpointer user_data)
{
	GError *err = NULL;
	gchar data[1];
	gsize bytes_read;

	/* Empty the pipe */
	if (G_IO_STATUS_NORMAL != 
	    g_io_channel_read_chars (source, data, 1, &bytes_read, &err)) {
		g_warning ("Error emptying sigusr1 pipe: %s", err->message);
		g_error_free (err);
		goto out;
	}

	g_debug ("Caught SIGUSR1");
	if (manager != NULL) {
		polkit_manager_update_desktop_console_privileges (manager);
	}

out:
	return TRUE;
}


int
main (int argc, char *argv[])
{
	DBusGConnection *bus;
	DBusGProxy *bus_proxy;
	GError *error = NULL;
	GMainLoop *mainloop;
	guint request_name_result;
	int ret;
	gboolean no_daemon = FALSE;
	gboolean is_verbose = FALSE;
	int pf;
	ssize_t written;
	char pid[9];
	guint sigusr1_iochn_listener_source_id;
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
	} else {
		g_debug (("not becoming a daemon"));
	}

	/* remove old pid file */
	unlink (POLKITD_PID_FILE);

	/* make a new pid file */
	if ((pf = open (POLKITD_PID_FILE, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644)) > 0) {
		snprintf (pid, sizeof(pid), "%lu\n", (long unsigned) getpid ());
		written = write (pf, pid, strlen(pid));
		close (pf);
		g_atexit (delete_pid);
	}

	g_type_init ();

	dbus_g_object_type_install_info (POLKIT_TYPE_MANAGER, &dbus_glib_polkit_manager_object_info);
	dbus_g_object_type_install_info (POLKIT_TYPE_SESSION, &dbus_glib_polkit_session_object_info);
	dbus_g_error_domain_register (POLKIT_MANAGER_ERROR, NULL, POLKIT_MANAGER_TYPE_ERROR);
	dbus_g_error_domain_register (POLKIT_SESSION_ERROR, NULL, POLKIT_SESSION_TYPE_ERROR);

	mainloop = g_main_loop_new (NULL, FALSE);

	/* Listen for SIGUSR1 - UNIX signal handlers are evil though,
	 * so set up a pipe to transmit the signal.
	 */

	/* create pipe */
	if (pipe (sigusr1_unix_signal_pipe_fds) != 0) {
		g_warning ("Could not setup pipe, errno=%d", errno);
		goto out;
	}
	
	/* setup glib handler - 0 is for reading, 1 is for writing */
	sigusr1_iochn = g_io_channel_unix_new (sigusr1_unix_signal_pipe_fds[0]);
	if (sigusr1_iochn == NULL) {
		g_warning ("Could not create GIOChannel");
		goto out;
	}
	
	/* get callback when there is data to read */
	sigusr1_iochn_listener_source_id = g_io_add_watch (
		sigusr1_iochn, G_IO_IN, sigusr1_iochn_data, NULL);

	/* setup UNIX signal handler for SIGUSR1 */
	signal (SIGUSR1, handle_sigusr1);

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

	if (request_name_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		g_warning ("There is already a primary owner of the name org.freedesktop.PolicyKit");
		goto out;
	}
	

	manager = polkit_manager_new (bus, bus_proxy);
	if (manager == NULL) {
		g_warning ("Could not construct manager object; bailing out");
		goto out;
	}

	g_debug ("service running");

	polkit_manager_update_desktop_console_privileges (manager);

	g_main_loop_run (mainloop);

	ret = 0;
out:
	return ret;
}

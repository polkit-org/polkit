/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 David Zeuthen <david@fubar.dk>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glib-object.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "polkit-daemon.h"

#define NAME_TO_CLAIM "org.freedesktop.PolicyKit"

static gboolean
acquire_name_on_proxy (DBusGProxy *bus_proxy)
{
        GError     *error;
        guint       result;
        gboolean    res;
        gboolean    ret;

        ret = FALSE;

        if (bus_proxy == NULL) {
                goto out;
        }

        error = NULL;
	res = dbus_g_proxy_call (bus_proxy,
                                 "RequestName",
                                 &error,
                                 G_TYPE_STRING, NAME_TO_CLAIM,
                                 G_TYPE_UINT, 0,
                                 G_TYPE_INVALID,
                                 G_TYPE_UINT, &result,
                                 G_TYPE_INVALID);
        if (! res) {
                if (error != NULL) {
                        g_warning ("Failed to acquire %s: %s", NAME_TO_CLAIM, error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to acquire %s", NAME_TO_CLAIM);
                }
                goto out;
	}

 	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
                if (error != NULL) {
                        g_warning ("Failed to acquire %s: %s", NAME_TO_CLAIM, error->message);
                        g_error_free (error);
                } else {
                        g_warning ("Failed to acquire %s", NAME_TO_CLAIM);
                }
                goto out;
        }

        ret = TRUE;

 out:
        return ret;
}

int
main (int argc, char **argv)
{
        GError              *error;
        GMainLoop           *loop;
        PolKitDaemon        *daemon;
        GOptionContext      *context;
        DBusGProxy          *bus_proxy;
        DBusGConnection     *bus;
        int                  ret;
	struct passwd *pw = NULL;
	struct group *gr = NULL;
        static gboolean     no_exit      = FALSE;
        static GOptionEntry entries []   = {
                { "no-exit", 0, 0, G_OPTION_ARG_NONE, &no_exit, "Don't exit after 30 seconds of inactivity", NULL },
                { NULL }
        };

        ret = 1;

	pw = getpwnam (POLKIT_USER);
	if (pw == NULL)  {
		g_warning ("polkitd: user " POLKIT_USER " does not exist");
                goto out;
	}

	gr = getgrnam (POLKIT_GROUP);
	if (gr == NULL) {
		g_warning ("polkitd: group " POLKIT_GROUP " does not exist");
		goto out;
	}

        if (initgroups (POLKIT_USER, gr->gr_gid)) {
                g_warning ("polkitd: could not initialize groups");
                goto out;
        }

	if (setgid (gr->gr_gid)) {
		g_warning ("polkitd: could not set group id");
		goto out;
	}

	if (setuid (pw->pw_uid)) {
		g_warning ("polkitd: could not set user id");
		goto out;
	}


        g_type_init ();

        context = g_option_context_new ("PolicyKit daemon");
        g_option_context_add_main_entries (context, entries, NULL);
        g_option_context_parse (context, &argc, &argv, NULL);
        g_option_context_free (context);

        error = NULL;
        bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                g_warning ("Couldn't connect to system bus: %s", error->message);
                g_error_free (error);
                goto out;
        }

	bus_proxy = dbus_g_proxy_new_for_name (bus,
                                               DBUS_SERVICE_DBUS,
                                               DBUS_PATH_DBUS,
                                               DBUS_INTERFACE_DBUS);
        if (bus_proxy == NULL) {
                g_warning ("Could not construct bus_proxy object; bailing out");
                goto out;
        }

        if (!acquire_name_on_proxy (bus_proxy) ) {
                g_warning ("Could not acquire name; bailing out");
                goto out;
        }

        g_debug ("Starting polkitd version %s", VERSION);

        daemon = polkit_daemon_new (no_exit);

        if (daemon == NULL) {
                goto out;
        }

        loop = g_main_loop_new (NULL, FALSE);

        g_main_loop_run (loop);

        g_object_unref (daemon);
        g_main_loop_unref (loop);
        ret = 0;

out:
        return ret;
}

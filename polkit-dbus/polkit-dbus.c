/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-dbus.h : helper library for obtaining seat, session and
 * caller information via D-Bus and ConsoleKit
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

/**
 * SECTION:polkit-dbus
 * @short_description: Helper library for obtaining seat, session and
 * caller information via D-Bus and ConsoleKit.
 *
 * Helper library for obtaining seat, session and caller information
 * via D-Bus and ConsoleKit. This library is only useful when writing
 * a mechanism. If the mechanism itself is a daemon exposing a remote
 * services (via e.g. D-Bus) it's often a better idea, to reduce
 * roundtrips, to track and cache caller information and construct
 * #PolKitCaller objects yourself based on this information (for an
 * example of this, see the hald sources on how this can be done).
 **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <glib.h>
#include <string.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "polkit-dbus.h"


/**
 * polkit_session_new_from_objpath:
 * @con: D-Bus system bus connection
 * @objpath: object path of ConsoleKit session object
 * @uid: the user owning the session or -1 if unknown
 * @error: D-Bus error
 * 
 * This function will construct a #PolKitSession object by querying
 * the ConsoleKit daemon for information. Note that this will do a lot
 * of blocking IO so it is best avoided if your process already
 * tracks/caches all the information. If you pass in @uid as a
 * non-negative number, a round trip can be saved.
 * 
 * Returns: the new object or #NULL if an error occured (in which case
 * @error will be set)
 **/
PolKitSession *
polkit_session_new_from_objpath (DBusConnection *con, const char *objpath, uid_t uid, DBusError *error)
{
        PolKitSeat *seat;
        PolKitSession *session;
        DBusMessage *message;
        DBusMessage *reply;
        char *str;
        dbus_bool_t is_active;
        dbus_bool_t is_local;
        char *remote_host;
        char *seat_path;

        g_return_val_if_fail (con != NULL, NULL);
        g_return_val_if_fail (objpath != NULL, NULL);
        g_return_val_if_fail (error != NULL, NULL);
        g_return_val_if_fail (! dbus_error_is_set (error), NULL);

        session = NULL;
        remote_host = NULL;
        seat_path = NULL;

	message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
						objpath,
						"org.freedesktop.ConsoleKit.Session",
						"IsActive");
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
		g_warning ("Error doing Session.IsActive on ConsoleKit: %s: %s", error->name, error->message);
		dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
		goto out;
	}
	if (!dbus_message_get_args (reply, NULL,
				    DBUS_TYPE_BOOLEAN, &is_active,
                                    DBUS_TYPE_INVALID)) {
                g_warning ("Invalid IsActive reply from CK");
		goto out;
	}
	dbus_message_unref (message);
	dbus_message_unref (reply);

	message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
						objpath,
						"org.freedesktop.ConsoleKit.Session",
						"IsLocal");
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
		g_warning ("Error doing Session.IsLocal on ConsoleKit: %s: %s", error->name, error->message);
		dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
		goto out;
	}
	if (!dbus_message_get_args (reply, NULL,
				    DBUS_TYPE_BOOLEAN, &is_local,
				    DBUS_TYPE_INVALID)) {
		g_warning ("Invalid IsLocal reply from CK");
		goto out;
	}
	dbus_message_unref (message);
	dbus_message_unref (reply);

        if (!is_local) {
                message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
                                                        objpath,
                                                        "org.freedesktop.ConsoleKit.Session",
                                                        "GetRemoteHostName");
                reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
                if (reply == NULL || dbus_error_is_set (error)) {
                        g_warning ("Error doing Session.GetRemoteHostName on ConsoleKit: %s: %s", 
                                   error->name, error->message);
                        dbus_message_unref (message);
                        if (reply != NULL)
                                dbus_message_unref (reply);
                        goto out;
                }
                if (!dbus_message_get_args (reply, NULL,
                                            DBUS_TYPE_STRING, &str,
                                            DBUS_TYPE_INVALID)) {
                        g_warning ("Invalid GetRemoteHostName reply from CK");
                        goto out;
                }
                remote_host = g_strdup (str);
                dbus_message_unref (message);
                dbus_message_unref (reply);
        }

        message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
                                                objpath,
                                                "org.freedesktop.ConsoleKit.Session",
                                                "GetSeatId");
        reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
        if (reply == NULL || dbus_error_is_set (error)) {
                g_warning ("Error doing Session.GetSeatId on ConsoleKit: %s: %s", 
                           error->name, error->message);
                dbus_message_unref (message);
                if (reply != NULL)
                        dbus_message_unref (reply);
                goto out;
        }
        if (!dbus_message_get_args (reply, NULL,
                                    DBUS_TYPE_OBJECT_PATH, &str,
                                    DBUS_TYPE_INVALID)) {
                g_warning ("Invalid GetSeatId reply from CK");
                goto out;
        }
        seat_path = g_strdup (str);
        dbus_message_unref (message);
        dbus_message_unref (reply);

        if ((int) uid == -1) {
                message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
                                                        objpath,
                                                        "org.freedesktop.ConsoleKit.Session",
                                                        "GetUnixUser");
                reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
                if (reply == NULL || dbus_error_is_set (error)) {
                        g_warning ("Error doing Session.GetUnixUser on ConsoleKit: %s: %s",error->name, error->message);
                        dbus_message_unref (message);
                        if (reply != NULL)
                                dbus_message_unref (reply);
                        goto out;
                }
                if (!dbus_message_get_args (reply, NULL,
                                            DBUS_TYPE_INT32, &uid,
                                            DBUS_TYPE_INVALID)) {
                        g_warning ("Invalid GetUnixUser reply from CK");
                        goto out;
                }
                dbus_message_unref (message);
                dbus_message_unref (reply);
        }

        session = polkit_session_new ();
        if (session == NULL) {
                goto out;
        }
        if (!polkit_session_set_ck_objref (session, objpath)) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }
        if (!polkit_session_set_ck_is_active (session, is_active)) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }
        if (!polkit_session_set_ck_is_local (session, is_local)) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }
        if (!is_local) {
                if (!polkit_session_set_ck_remote_host (session, remote_host)) {
                        polkit_session_unref (session);
                        session = NULL;
                        goto out;
                }

        }

        seat = polkit_seat_new ();
        if (seat == NULL) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }
        if (!polkit_seat_set_ck_objref (seat, seat_path)) {
                polkit_seat_unref (seat);
                seat = NULL;
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }
        if (!polkit_seat_validate (seat)) {
                polkit_seat_unref (seat);
                seat = NULL;
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }

        if (!polkit_session_set_seat (session, seat)) {
                polkit_seat_unref (seat);
                seat = NULL;
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }
        polkit_seat_unref (seat); /* session object now owns this object */
        seat = NULL;

        if (!polkit_session_validate (session)) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }

out:
        g_free (remote_host);
        g_free (seat_path);
        return session;
}

/**
 * polkit_session_new_from_cookie:
 * @con: D-Bus system bus connection
 * @cookie: a ConsoleKit XDG_SESSION_COOKIE
 * @error: D-Bus error
 * 
 * This function will construct a #PolKitSession object by querying
 * the ConsoleKit daemon for information. Note that this will do a lot
 * of blocking IO so it is best avoided if your process already
 * tracks/caches all the information.
 * 
 * Returns: the new object or #NULL if an error occured (in which case
 * @error will be set)
 **/
PolKitSession *
polkit_session_new_from_cookie (DBusConnection *con, const char *cookie, DBusError *error)
{
        PolKitSession *session;
        DBusMessage *message;
        DBusMessage *reply;
        char *str;
        char *objpath;

        g_return_val_if_fail (con != NULL, NULL);
        g_return_val_if_fail (cookie != NULL, NULL);
        g_return_val_if_fail (error != NULL, NULL);
        g_return_val_if_fail (! dbus_error_is_set (error), NULL);

        objpath = NULL;
        session = NULL;

	message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
						"/org/freedesktop/ConsoleKit/Manager",
						"org.freedesktop.ConsoleKit.Manager",
						"GetSessionForCookie");
	dbus_message_append_args (message, DBUS_TYPE_STRING, &cookie, DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
		g_warning ("Error doing Manager.GetSessionForCookie on ConsoleKit: %s: %s", 
                           error->name, error->message);
		dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
		goto out;
	}
	if (!dbus_message_get_args (reply, NULL,
				    DBUS_TYPE_OBJECT_PATH, &str,
                                    DBUS_TYPE_INVALID)) {
                g_warning ("Invalid GetSessionForCookie reply from CK");
		goto out;
	}
        objpath = g_strdup (str);
	dbus_message_unref (message);
	dbus_message_unref (reply);

        session = polkit_session_new_from_objpath (con, objpath, -1, error);

out:
        g_free (objpath);
        return session;
}


/**
 * polkit_caller_new_from_dbus_name:
 * @con: D-Bus system bus connection
 * @dbus_name: unique system bus connection name
 * @error: D-Bus error
 * 
 * This function will construct a #PolKitCaller object by querying
 * both the system bus daemon and the ConsoleKit daemon for
 * information. Note that this will do a lot of blocking IO so it is
 * best avoided if your process already tracks/caches all the
 * information.
 * 
 * Returns: the new object or #NULL if an error occured (in which case
 * @error will be set)
 **/
PolKitCaller *
polkit_caller_new_from_dbus_name (DBusConnection *con, const char *dbus_name, DBusError *error)
{
        PolKitCaller *caller;
        pid_t pid;
        uid_t uid;
        char *selinux_context;
        char *ck_session_objpath;
        PolKitSession *session;
        DBusMessage *message;
        DBusMessage *reply;
        DBusMessageIter iter;
        DBusMessageIter sub_iter;
        char *str;
        int num_elems;

        g_return_val_if_fail (con != NULL, NULL);
        g_return_val_if_fail (dbus_name != NULL, NULL);
        g_return_val_if_fail (error != NULL, NULL);
        g_return_val_if_fail (! dbus_error_is_set (error), NULL);

        selinux_context = NULL;
        ck_session_objpath = NULL;

        caller = NULL;
        session = NULL;

	uid = dbus_bus_get_unix_user (con, dbus_name, error);
	if (uid == ((unsigned long) -1) || dbus_error_is_set (error)) {
		g_warning ("Could not get uid for connection: %s %s", error->name, error->message);
		goto out;
	}

	message = dbus_message_new_method_call ("org.freedesktop.DBus", 
						"/org/freedesktop/DBus/Bus",
						"org.freedesktop.DBus",
						"GetConnectionUnixProcessID");
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &dbus_name);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
		g_warning ("Error doing GetConnectionUnixProcessID on Bus: %s: %s", error->name, error->message);
		dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
		goto out;
	}
	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_get_basic (&iter, &pid);
	dbus_message_unref (message);
	dbus_message_unref (reply);

	message = dbus_message_new_method_call ("org.freedesktop.DBus", 
						"/org/freedesktop/DBus/Bus",
						"org.freedesktop.DBus",
						"GetConnectionSELinuxSecurityContext");
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &dbus_name);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
        /* SELinux might not be enabled */
        if (dbus_error_is_set (error) && 
            strcmp (error->name, "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown") == 0) {
                dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
                dbus_error_init (error);
        } else if (reply == NULL || dbus_error_is_set (error)) {
                g_warning ("Error doing GetConnectionSELinuxSecurityContext on Bus: %s: %s", error->name, error->message);
                dbus_message_unref (message);
                if (reply != NULL)
                        dbus_message_unref (reply);
                goto out;
        } else {
                /* TODO: verify signature */
                dbus_message_iter_init (reply, &iter);
                dbus_message_iter_recurse (&iter, &sub_iter);
                dbus_message_iter_get_fixed_array (&sub_iter, (void *) &str, &num_elems);
                if (str != NULL && num_elems > 0)
                        selinux_context = g_strndup (str, num_elems);
                dbus_message_unref (message);
                dbus_message_unref (reply);
        }

	message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
						"/org/freedesktop/ConsoleKit/Manager",
						"org.freedesktop.ConsoleKit.Manager",
						"GetSessionForUnixProcess");
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_UINT32, &pid);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
		g_warning ("Error doing GetSessionForUnixProcess on ConsoleKit: %s: %s", error->name, error->message);
		dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
		/* OK, this is not a catastrophe; just means the caller is not a 
                 * member of any session or that ConsoleKit is not available.. 
                 */
		goto not_in_session;
	}
	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_get_basic (&iter, &str);
	ck_session_objpath = g_strdup (str);
	dbus_message_unref (message);
	dbus_message_unref (reply);

        session = polkit_session_new_from_objpath (con, ck_session_objpath, uid, error);
        if (session == NULL) {
                g_warning ("Got a session objpath but couldn't construct session object!");
                goto out;
        }
        if (!polkit_session_validate (session)) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }

not_in_session:

        caller = polkit_caller_new ();
        if (caller == NULL) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                goto out;
        }

        if (!polkit_caller_set_dbus_name (caller, dbus_name)) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }
        if (!polkit_caller_set_uid (caller, uid)) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }
        if (!polkit_caller_set_pid (caller, pid)) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }
        if (selinux_context != NULL) {
                if (!polkit_caller_set_selinux_context (caller, selinux_context)) {
                        if (session != NULL) {
                                polkit_session_unref (session);
                                session = NULL;
                        }
                        polkit_caller_unref (caller);
                        caller = NULL;
                        goto out;
                }
        }
        if (session != NULL) {
                if (!polkit_caller_set_ck_session (caller, session)) {
                        if (session != NULL) {
                                polkit_session_unref (session);
                                session = NULL;
                        }
                        polkit_caller_unref (caller);
                        caller = NULL;
                        goto out;
                }
                polkit_session_unref (session); /* caller object now own this object */
                session = NULL;
        }

        if (!polkit_caller_validate (caller)) {
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }

out:
        g_free (selinux_context);
        g_free (ck_session_objpath);
        return caller;
}

/**
 * polkit_caller_new_from_pid:
 * @con: D-Bus system bus connection
 * @pid: process id
 * @error: D-Bus error
 * 
 * This function will construct a #PolKitCaller object by querying
 * both information in /proc (on Linux) and the ConsoleKit daemon for
 * information about a given process. Note that this will do a lot of
 * blocking IO so it is best avoided if your process already
 * tracks/caches all the information.
 * 
 * Returns: the new object or #NULL if an error occured (in which case
 * @error will be set)
 **/
PolKitCaller *
polkit_caller_new_from_pid (DBusConnection *con, pid_t pid, DBusError *error)
{
        PolKitCaller *caller;
        uid_t uid;
        char *selinux_context;
        char *ck_session_objpath;
        PolKitSession *session;
        DBusMessage *message;
        DBusMessage *reply;
        DBusMessageIter iter;
        char *str;
        char *proc_path;
        struct stat statbuf;
#ifdef HAVE_SELINUX
        security_context_t secon;
#endif

        g_return_val_if_fail (con != NULL, NULL);
        g_return_val_if_fail (error != NULL, NULL);
        g_return_val_if_fail (! dbus_error_is_set (error), NULL);

        selinux_context = NULL;
        ck_session_objpath = NULL;
        caller = NULL;
        session = NULL;
        proc_path = NULL;

        proc_path = g_strdup_printf ("/proc/%d", pid);
        if (stat (proc_path, &statbuf) != 0) {
                g_warning ("Cannot lookup information for pid %d: %s", pid, strerror (errno));
                goto out;
        }
        uid = statbuf.st_uid;

#ifdef HAVE_SELINUX
        if (getpidcon (pid, &secon) != 0) {
                g_warning ("Cannot lookup SELinux context for pid %d: %s", pid, strerror (errno));
                goto out;
        }
        selinux_context = g_strdup (secon);
        freecon (secon);
#else
        selinux_context = NULL;
#endif

	message = dbus_message_new_method_call ("org.freedesktop.ConsoleKit", 
						"/org/freedesktop/ConsoleKit/Manager",
						"org.freedesktop.ConsoleKit.Manager",
						"GetSessionForUnixProcess");
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_UINT32, &pid);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
		g_warning ("Error doing GetSessionForUnixProcess on ConsoleKit: %s: %s", error->name, error->message);
		dbus_message_unref (message);
		if (reply != NULL)
			dbus_message_unref (reply);
		/* OK, this is not a catastrophe; just means the caller is not a 
                 * member of any session or that ConsoleKit is not available.. 
                 */
		goto not_in_session;
	}
	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_get_basic (&iter, &str);
	ck_session_objpath = g_strdup (str);
	dbus_message_unref (message);
	dbus_message_unref (reply);

        session = polkit_session_new_from_objpath (con, ck_session_objpath, uid, error);
        if (session == NULL) {
                g_warning ("Got a session objpath but couldn't construct session object!");
                goto out;
        }
        if (!polkit_session_validate (session)) {
                polkit_session_unref (session);
                session = NULL;
                goto out;
        }

not_in_session:

        caller = polkit_caller_new ();
        if (caller == NULL) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                goto out;
        }

        if (!polkit_caller_set_uid (caller, uid)) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }
        if (!polkit_caller_set_pid (caller, pid)) {
                if (session != NULL) {
                        polkit_session_unref (session);
                        session = NULL;
                }
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }
        if (selinux_context != NULL) {
                if (!polkit_caller_set_selinux_context (caller, selinux_context)) {
                        if (session != NULL) {
                                polkit_session_unref (session);
                                session = NULL;
                        }
                        polkit_caller_unref (caller);
                        caller = NULL;
                        goto out;
                }
        }
        if (session != NULL) {
                if (!polkit_caller_set_ck_session (caller, session)) {
                        if (session != NULL) {
                                polkit_session_unref (session);
                                session = NULL;
                        }
                        polkit_caller_unref (caller);
                        caller = NULL;
                        goto out;
                }
                polkit_session_unref (session); /* caller object now own this object */
                session = NULL;
        }

        if (!polkit_caller_validate (caller)) {
                polkit_caller_unref (caller);
                caller = NULL;
                goto out;
        }

out:
        g_free (selinux_context);
        g_free (ck_session_objpath);
        g_free (proc_path);
        return caller;
}

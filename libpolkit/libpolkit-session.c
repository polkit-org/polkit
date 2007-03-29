/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-session.c : sessions
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "libpolkit-session.h"


/**
 * SECTION:libpolkit-session
 * @short_description: Sessions.
 *
 * This class is used to represent a session. TODO: describe session.
 **/

/**
 * PolKitSession:
 *
 * Objects of this class are used to record information about a
 * session.
 **/
struct PolKitSession
{
        int refcount;
        uid_t uid;
        PolKitSeat *seat;
        char *ck_objref;
        gboolean is_active;
        gboolean is_local;
        char *remote_host;
};

/**
 * libpolkit_session_new:
 * 
 * Creates a new #PolKitSession object.
 * 
 * Returns: the new object
 **/
PolKitSession *
libpolkit_session_new (void)
{
        PolKitSession *session;
        session = g_new0 (PolKitSession, 1);
        session->refcount = 1;
        return session;
}

/**
 * libpolkit_session_ref:
 * @session: The session object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitSession *
libpolkit_session_ref (PolKitSession *session)
{
        g_return_val_if_fail (session != NULL, session);
        session->refcount++;
        return session;
}


/**
 * libpolkit_session_unref:
 * @session: The session object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void 
libpolkit_session_unref (PolKitSession *session)
{
        g_return_if_fail (session != NULL);
        session->refcount--;
        if (session->refcount > 0) 
                return;
        g_free (session->ck_objref);
        g_free (session->remote_host);
        if (session->seat != NULL)
                libpolkit_seat_unref (session->seat);
        g_free (session);
}

/**
 * libpolkit_session_set_uid:
 * @session: The session object
 * @uid: UNIX user id
 * 
 * Set the UNIX user id of the user owning the session.
 **/
void 
libpolkit_session_set_uid (PolKitSession *session, uid_t uid)
{
        g_return_if_fail (session != NULL);
        session->uid = uid;
}

/**
 * libpolkit_session_set_ck_objref:
 * @session: The session object
 * @ck_objref: D-Bus object path
 * 
 * Set the D-Bus object path to the ConsoleKit session object.
 **/
void 
libpolkit_session_set_ck_objref (PolKitSession *session, const char *ck_objref)
{
        g_return_if_fail (session != NULL);
        if (session->ck_objref != NULL)
                g_free (session->ck_objref);
        session->ck_objref = g_strdup (ck_objref);
}

/**
 * libpolkit_session_set_ck_is_active:
 * @session: The session object
 * @is_active: whether ConsoleKit reports the session as active
 * 
 * Set whether ConsoleKit regard the session as active.
 **/
void 
libpolkit_session_set_ck_is_active (PolKitSession *session, gboolean is_active)
{
        g_return_if_fail (session != NULL);
        session->is_active = is_active;
}

/**
 * libpolkit_session_set_ck_is_local:
 * @session: The session object
 * @is_local: whether ConsoleKit reports the session as local
 * 
 * Set whether ConsoleKit regard the session as local.
 **/
void 
libpolkit_session_set_ck_is_local (PolKitSession *session, gboolean is_local)
{
        g_return_if_fail (session != NULL);
        session->is_local = is_local;
}

/**
 * libpolkit_session_set_ck_remote_host:
 * @session: The session object
 * @remote_host: hostname of the host/display that ConsoleKit reports
 * the session to occur at
 * 
 * Set the remote host/display that ConsoleKit reports the session to
 * occur at.
 **/
void 
libpolkit_session_set_ck_remote_host (PolKitSession *session, const char *remote_host)
{
        g_return_if_fail (session != NULL);
        if (session->remote_host != NULL)
                g_free (session->remote_host);
        session->remote_host = g_strdup (remote_host);
}

/**
 * libpolkit_session_set_seat:
 * @session: The session object
 * @seat: a #PolKitSeat object
 * 
 * Set the seat that the session belongs to. The reference count on
 * the given object will be increased by one. If an existing seat
 * object was set already, the reference count on that one will be
 * decreased by one.
 **/
void 
libpolkit_session_set_seat (PolKitSession *session, PolKitSeat *seat)
{
        g_return_if_fail (session != NULL);
        if (session->seat != NULL)
                libpolkit_seat_unref (session->seat);
        session->seat = seat != NULL ? libpolkit_seat_ref (seat) : NULL;
}

/**
 * libpolkit_session_get_uid:
 * @session: The session object
 * @out_uid: UNIX user id
 * 
 * Get the UNIX user id of the user owning the session.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_session_get_uid (PolKitSession *session, uid_t *out_uid)
{
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_uid != NULL, FALSE);
        *out_uid = session->uid;
        return TRUE;
}

/**
 * libpolkit_session_get_ck_objref:
 * @session: The session object
 * @out_ck_objref: D-Bus object path. Shall not be freed by the caller.
 * 
 * Get the D-Bus object path to the ConsoleKit session object.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_session_get_ck_objref (PolKitSession *session, char **out_ck_objref)
{
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_ck_objref != NULL, FALSE);
        *out_ck_objref = session->ck_objref;
        return TRUE;
}

/**
 * libpolkit_session_get_ck_is_active:
 * @session: The session object
 * @out_is_active: whether ConsoleKit reports the session as active
 * 
 * Get whether ConsoleKit regard the session as active.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_session_get_ck_is_active (PolKitSession *session, gboolean *out_is_active)
{
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_is_active != NULL, FALSE);
        *out_is_active = session->is_active;
        return TRUE;
}

/**
 * libpolkit_session_get_ck_is_local:
 * @session: The session object
 * @out_is_local: whether ConsoleKit reports the session as local
 * 
 * Set whether ConsoleKit regard the session as local.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_session_get_ck_is_local (PolKitSession *session, gboolean *out_is_local)
{
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_is_local != NULL, FALSE);
        *out_is_local = session->is_local;
        return TRUE;
}

/**
 * libpolkit_session_get_ck_remote_host:
 * @session: The session object
 * @out_remote_host: hostname of the host/display that ConsoleKit
 * reports the session to occur at. Shall not be freed by the caller.
 * 
 * Get the remote host/display that ConsoleKit reports the session to
 * occur at.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_session_get_ck_remote_host (PolKitSession *session, char **out_remote_host)
{
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_remote_host != NULL, FALSE);
        *out_remote_host = session->remote_host;
        return TRUE;
}

/**
 * libpolkit_session_get_seat:
 * @session: The session object
 * @out_seat: Returns the seat the session belongs to. Shall not
 * be unreffed by the caller.
 * 
 * Get the seat that the session belongs to.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_session_get_seat (PolKitSession *session, PolKitSeat **out_seat)
{
        g_return_val_if_fail (session != NULL, FALSE);
        g_return_val_if_fail (out_seat != NULL, FALSE);
        *out_seat = session->seat;
        return TRUE;
}

/**
 * libpolkit_session_new_from_objpath:
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
libpolkit_session_new_from_objpath (DBusConnection *con, const char *objpath, uid_t uid, DBusError *error)
{
        PolKitSeat *seat;
        PolKitSession *session;
        DBusMessage *message;
        DBusMessage *reply;
        char *str;
        gboolean is_active;
        gboolean is_local;
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

        g_debug ("is_active %d", is_active);
        g_debug ("is_local %d", is_local);
        g_debug ("uid %d", uid);
        if (!is_local) {
                g_debug ("remote host '%s'", remote_host);
        }
        g_debug ("ck seat '%s'", seat_path);

        session = libpolkit_session_new ();
        libpolkit_session_set_ck_is_active (session, is_active);
        libpolkit_session_set_ck_is_local (session, is_local);
        if (!is_local) {
                libpolkit_session_set_ck_remote_host (session, remote_host);
        }
        seat = libpolkit_seat_new ();
        libpolkit_seat_set_ck_objref (seat, seat_path);
        libpolkit_session_set_seat (session, seat);
        libpolkit_seat_unref (seat); /* we own this now */

out:
        g_free (remote_host);
        g_free (seat_path);
        return session;
}

/**
 * libpolkit_session_new_from_cookie:
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
libpolkit_session_new_from_cookie (DBusConnection *con, const char *cookie, DBusError *error)
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

        session = libpolkit_session_new_from_objpath (con, objpath, -1, error);

out:
        g_free (objpath);
        return session;
}


/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-caller.c : callers
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
 * SECTION:libpolkit-caller
 * @short_description: Callers on the system message bus.
 *
 * This class is used to represent a caller in another process connected to the system message bus.
 **/

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
#include "libpolkit-debug.h"
#include "libpolkit-caller.h"

/**
 * PolKitCaller:
 *
 * Objects of this class are used to record information about a caller
 * on the system bus.
 **/
struct PolKitCaller
{
        int refcount;
        char *dbus_name;
        pid_t uid;
        pid_t pid;
        char *selinux_context;
        PolKitSession *session;
};

/**
 * libpolkit_caller_new:
 *
 * Creates a new #PolKitCaller object.
 *
 * Returns: the new object
 **/
PolKitCaller *
libpolkit_caller_new (void)
{
        PolKitCaller *caller;
        caller = g_new0 (PolKitCaller, 1);
        caller->refcount = 1;
        return caller;
}

/**
 * libpolkit_caller_ref:
 * @caller: The caller object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitCaller *
libpolkit_caller_ref (PolKitCaller *caller)
{
        g_return_val_if_fail (caller != NULL, caller);
        caller->refcount++;
        return caller;
}


/**
 * libpolkit_caller_unref:
 * @caller: The caller object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_caller_unref (PolKitCaller *caller)
{
        g_return_if_fail (caller != NULL);
        caller->refcount--;
        if (caller->refcount > 0) 
                return;
        g_free (caller->dbus_name);
        g_free (caller->selinux_context);
        if (caller->session != NULL)
                libpolkit_session_unref (caller->session);
        g_free (caller);
}

/**
 * libpolkit_caller_set_dbus_name:
 * @caller: The caller object
 * @dbus_name: unique system bus connection name
 * 
 * Set the callers unique system bus connection name.
 **/
void
libpolkit_caller_set_dbus_name (PolKitCaller *caller, const char *dbus_name)
{
        g_return_if_fail (caller != NULL);
        if (caller->dbus_name != NULL)
                g_free (caller->dbus_name);
        caller->dbus_name = g_strdup (dbus_name);
}

/**
 * libpolkit_caller_set_uid:
 * @caller: The caller object 
 * @uid: UNIX user id
 * 
 * Set the callers UNIX user id.
 **/
void
libpolkit_caller_set_uid (PolKitCaller *caller, uid_t uid)
{
        g_return_if_fail (caller != NULL);
        caller->uid = uid;
}

/**
 * libpolkit_caller_set_pid:
 * @caller: The caller object 
 * @pid: UNIX process id
 * 
 * Set the callers UNIX process id.
 **/
void
libpolkit_caller_set_pid (PolKitCaller *caller, pid_t pid)
{
        g_return_if_fail (caller != NULL);
        caller->pid = pid;
}

/**
 * libpolkit_caller_set_selinux_context:
 * @caller: The caller object 
 * @selinux_context: SELinux security context
 * 
 * Set the callers SELinux security context.
 **/
void
libpolkit_caller_set_selinux_context (PolKitCaller *caller, const char *selinux_context)
{
        g_return_if_fail (caller != NULL);
        if (caller->selinux_context != NULL)
                g_free (caller->selinux_context);
        caller->selinux_context = g_strdup (selinux_context);
}

/**
 * libpolkit_caller_set_ck_session:
 * @caller: The caller object 
 * @session: a session object
 * 
 * Set the callers session. The reference count on the given object
 * will be increased by one. If an existing session object was set
 * already, the reference count on that one will be decreased by one.
 **/
void
libpolkit_caller_set_ck_session (PolKitCaller *caller, PolKitSession *session)
{
        g_return_if_fail (caller != NULL);
        if (caller->session != NULL)
                libpolkit_session_unref (caller->session);
        caller->session = session != NULL ? libpolkit_session_ref (session) : NULL;
}

/**
 * libpolkit_caller_get_dbus_name:
 * @caller: The caller object 
 * @out_dbus_name: Returns the unique system bus connection name. The caller shall not free this string.
 * 
 * Get the callers unique system bus connection name.
 * 
 * Returns: TRUE iff the value is returned
 **/
bool
libpolkit_caller_get_dbus_name (PolKitCaller *caller, char **out_dbus_name)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_dbus_name != NULL, FALSE);
        *out_dbus_name = caller->dbus_name;
        return TRUE;
}

/**
 * libpolkit_caller_get_uid:
 * @caller: The caller object 
 * @out_uid: Returns the UNIX user id
 * 
 * Get the callers UNIX user id.
 * 
 * Returns: TRUE iff the value is returned
 **/
bool
libpolkit_caller_get_uid (PolKitCaller *caller, uid_t *out_uid)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_uid != NULL, FALSE);
        *out_uid = caller->uid;
        return TRUE;
}

/**
 * libpolkit_caller_get_pid:
 * @caller: The caller object 
 * @out_pid: Returns the UNIX process id
 * 
 * Get the callers UNIX process id.
 * 
 * Returns: TRUE iff the value is returned
 **/
bool
libpolkit_caller_get_pid (PolKitCaller *caller, pid_t *out_pid)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_pid != NULL, FALSE);
        *out_pid = caller->pid;
        return TRUE;
}

/**
 * libpolkit_caller_get_selinux_context:
 * @caller: The caller object 
 * @out_selinux_context: Returns the SELinux security context. The caller shall not free this string.
 * 
 * Get the callers SELinux security context. Note that this may be
 * #NULL if SELinux is not available on the system.
 * 
 * Returns: TRUE iff the value is returned
 **/
bool
libpolkit_caller_get_selinux_context (PolKitCaller *caller, char **out_selinux_context)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_selinux_context != NULL, FALSE);
        *out_selinux_context = caller->selinux_context;
        return TRUE;
}

/**
 * libpolkit_caller_get_ck_session:
 * @caller: The caller object 
 * @out_session: Returns the session object. Caller shall not unref it.
 * 
 * Get the callers session. Note that this may be #NULL if the caller
 * is not in any session.
 * 
 * Returns: TRUE iff the value is returned
 **/
bool
libpolkit_caller_get_ck_session (PolKitCaller *caller, PolKitSession **out_session)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_session != NULL, FALSE);
        *out_session = caller->session;
        return TRUE;
}

/**
 * libpolkit_caller_new_from_dbus_name:
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
libpolkit_caller_new_from_dbus_name (DBusConnection *con, const char *dbus_name, DBusError *error)
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

        session = libpolkit_session_new_from_objpath (con, ck_session_objpath, uid, error);
        if (session == NULL) {
                g_warning ("Got a session objpath but couldn't construct session object!");
        }

not_in_session:
        _pk_debug ("uid %d", uid);
        _pk_debug ("pid %d", pid);
        _pk_debug ("selinux context '%s'", selinux_context != NULL ? selinux_context : "(not set)");
        _pk_debug ("ck session '%s'", ck_session_objpath != NULL ? ck_session_objpath : "(not in a session)");

        caller = libpolkit_caller_new ();
        libpolkit_caller_set_dbus_name (caller, dbus_name);
        libpolkit_caller_set_uid (caller, uid);
        libpolkit_caller_set_pid (caller, pid);
        libpolkit_caller_set_selinux_context (caller, selinux_context);
        if (session != NULL) {
                libpolkit_caller_set_ck_session (caller, session);
                libpolkit_session_unref (session); /* we own this session object */
        }

out:
        g_free (selinux_context);
        g_free (ck_session_objpath);
        return caller;
}

/**
 * libpolkit_caller_debug:
 * @caller: the object
 * 
 * Print debug details
 **/
void
libpolkit_caller_debug (PolKitCaller *caller)
{
        g_return_if_fail (caller != NULL);
        _pk_debug ("PolKitCaller: refcount=%d dbus_name=%s uid=%d pid=%d selinux_context=%s", 
                   caller->refcount, caller->dbus_name, caller->uid, caller->pid, caller->selinux_context);
        if (caller->session != NULL)
                libpolkit_session_debug (caller->session);
}

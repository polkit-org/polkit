/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-caller.c : callers
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
 * SECTION:polkit-caller
 * @title: Caller
 * @short_description: Represents a process requesting a mechanism to do something.
 *
 * This class is used to represent a caller in another process that is
 * calling into a mechanism to make the mechanism do something.
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
#include "polkit-debug.h"
#include "polkit-caller.h"
#include "polkit-utils.h"

/**
 * PolKitCaller:
 *
 * Objects of this class are used to record information about a caller
 * in another process.
 **/
struct _PolKitCaller
{
        int refcount;
        char *dbus_name;
        uid_t uid;
        pid_t pid;
        char *selinux_context;
        PolKitSession *session;
};

/**
 * polkit_caller_new:
 *
 * Creates a new #PolKitCaller object.
 *
 * Returns: the new object
 **/
PolKitCaller *
polkit_caller_new (void)
{
        PolKitCaller *caller;
        caller = g_new0 (PolKitCaller, 1);
        caller->refcount = 1;
        return caller;
}

/**
 * polkit_caller_ref:
 * @caller: The caller object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitCaller *
polkit_caller_ref (PolKitCaller *caller)
{
        g_return_val_if_fail (caller != NULL, caller);
        caller->refcount++;
        return caller;
}


/**
 * polkit_caller_unref:
 * @caller: The caller object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_caller_unref (PolKitCaller *caller)
{
        g_return_if_fail (caller != NULL);
        caller->refcount--;
        if (caller->refcount > 0) 
                return;
        g_free (caller->dbus_name);
        g_free (caller->selinux_context);
        if (caller->session != NULL)
                polkit_session_unref (caller->session);
        g_free (caller);
}

/**
 * polkit_caller_set_dbus_name:
 * @caller: The caller object
 * @dbus_name: unique system bus connection name
 * 
 * Set the callers unique system bus connection name.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_caller_set_dbus_name (PolKitCaller *caller, const char *dbus_name)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (_pk_validate_unique_bus_name (dbus_name), FALSE);
        if (caller->dbus_name != NULL)
                g_free (caller->dbus_name);
        caller->dbus_name = g_strdup (dbus_name);
        return TRUE;
}

/**
 * polkit_caller_set_uid:
 * @caller: The caller object 
 * @uid: UNIX user id
 * 
 * Set the callers UNIX user id.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_caller_set_uid (PolKitCaller *caller, uid_t uid)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        caller->uid = uid;
        return TRUE;
}

/**
 * polkit_caller_set_pid:
 * @caller: The caller object 
 * @pid: UNIX process id
 * 
 * Set the callers UNIX process id.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_caller_set_pid (PolKitCaller *caller, pid_t pid)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        caller->pid = pid;
        return TRUE;
}

/**
 * polkit_caller_set_selinux_context:
 * @caller: The caller object 
 * @selinux_context: SELinux security context
 * 
 * Set the callers SELinux security context.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_caller_set_selinux_context (PolKitCaller *caller, const char *selinux_context)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        /* TODO: probably should have a separate validation function for SELinux contexts */
        g_return_val_if_fail (_pk_validate_identifier (selinux_context), FALSE);

        if (caller->selinux_context != NULL)
                g_free (caller->selinux_context);
        caller->selinux_context = g_strdup (selinux_context);
        return TRUE;
}

/**
 * polkit_caller_set_ck_session:
 * @caller: The caller object 
 * @session: a session object
 * 
 * Set the callers session. The reference count on the given object
 * will be increased by one. If an existing session object was set
 * already, the reference count on that one will be decreased by one.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_caller_set_ck_session (PolKitCaller *caller, PolKitSession *session)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (polkit_session_validate (session), FALSE);
        if (caller->session != NULL)
                polkit_session_unref (caller->session);
        caller->session = session != NULL ? polkit_session_ref (session) : NULL;
        return TRUE;
}

/**
 * polkit_caller_get_dbus_name:
 * @caller: The caller object 
 * @out_dbus_name: Returns the unique system bus connection name. The caller shall not free this string.
 * 
 * Get the callers unique system bus connection name.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_caller_get_dbus_name (PolKitCaller *caller, char **out_dbus_name)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_dbus_name != NULL, FALSE);
        *out_dbus_name = caller->dbus_name;
        return TRUE;
}

/**
 * polkit_caller_get_uid:
 * @caller: The caller object 
 * @out_uid: Returns the UNIX user id
 * 
 * Get the callers UNIX user id.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_caller_get_uid (PolKitCaller *caller, uid_t *out_uid)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_uid != NULL, FALSE);
        *out_uid = caller->uid;
        return TRUE;
}

/**
 * polkit_caller_get_pid:
 * @caller: The caller object 
 * @out_pid: Returns the UNIX process id
 * 
 * Get the callers UNIX process id.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_caller_get_pid (PolKitCaller *caller, pid_t *out_pid)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_pid != NULL, FALSE);
        *out_pid = caller->pid;
        return TRUE;
}

/**
 * polkit_caller_get_selinux_context:
 * @caller: The caller object 
 * @out_selinux_context: Returns the SELinux security context. The caller shall not free this string.
 * 
 * Get the callers SELinux security context. Note that this may be
 * #NULL if SELinux is not available on the system.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_caller_get_selinux_context (PolKitCaller *caller, char **out_selinux_context)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_selinux_context != NULL, FALSE);
        *out_selinux_context = caller->selinux_context;
        return TRUE;
}

/**
 * polkit_caller_get_ck_session:
 * @caller: The caller object 
 * @out_session: Returns the session object. Caller shall not unref it.
 * 
 * Get the callers session. Note that this may be #NULL if the caller
 * is not in any session.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_caller_get_ck_session (PolKitCaller *caller, PolKitSession **out_session)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (out_session != NULL, FALSE);
        *out_session = caller->session;
        return TRUE;
}

/**
 * polkit_caller_debug:
 * @caller: the object
 * 
 * Print debug details
 **/
void
polkit_caller_debug (PolKitCaller *caller)
{
        g_return_if_fail (caller != NULL);
        _pk_debug ("PolKitCaller: refcount=%d dbus_name=%s uid=%d pid=%d selinux_context=%s", 
                   caller->refcount, caller->dbus_name, caller->uid, caller->pid, caller->selinux_context);
        if (caller->session != NULL)
                polkit_session_debug (caller->session);
}


/**
 * polkit_caller_validate:
 * @caller: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 **/
polkit_bool_t
polkit_caller_validate (PolKitCaller *caller)
{
        g_return_val_if_fail (caller != NULL, FALSE);
        g_return_val_if_fail (caller->pid > 0, FALSE);
        return TRUE;
}

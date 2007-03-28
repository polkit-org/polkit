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
#include "libpolkit-caller.h"

/**
 * PolKitCaller:
 *
 * Objects of this class are used to record information about a caller
 * on the system bus.
 **/
struct PolKitCaller
{
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
        return NULL;
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
        return caller;
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
gboolean
libpolkit_caller_get_dbus_name (PolKitCaller *caller, char **out_dbus_name)
{
        return FALSE;
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
gboolean
libpolkit_caller_get_uid (PolKitCaller *caller, uid_t *out_uid)
{
        return FALSE;
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
gboolean
libpolkit_caller_get_pid (PolKitCaller *caller, uid_t *out_pid)
{
        return FALSE;
}

/**
 * libpolkit_caller_get_selinux_context:
 * @caller: The caller object 
 * @out_selinux_context: Returns the SELinux security context. The caller shall not free this string.
 * 
 * Get the callers SELinux security context.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_caller_get_selinux_context (PolKitCaller *caller, char *out_selinux_context)
{
        return FALSE;
}

/**
 * libpolkit_caller_get_ck_session:
 * @caller: The caller object 
 * @out_session: Returns the session object. Caller shall not unref it.
 * 
 * Get the callers session.
 * 
 * Returns: TRUE iff the value is returned
 **/
gboolean
libpolkit_caller_get_ck_session (PolKitCaller *caller, PolKitSession **out_session)
{
        return FALSE;
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
}

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
        return NULL;
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
        return NULL;
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
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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
libpolkit_session_get_ck_remote_host (PolKitSession *session, char *out_remote_host)
{
        return FALSE;
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
        return FALSE;
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
}

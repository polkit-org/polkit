/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit.c : library for querying system-wide policy
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
#include "libpolkit.h"

struct PolKitContext_s
{
};

PolKitContext *
libpolkit_context_new (void)
{
        return FALSE;
}

PolKitContext *
libpolkit_context_ref (PolKitContext *pk_context)
{
        return pk_context;
}

void
libpolkit_context_set_config_changed (PolKitContext                *pk_context, 
                                      PolKitContextConfigChangedCB cb, 
                                      gpointer                     user_data)
{
}

void
libpolkit_context_unref (PolKitContext *pk_context)
{
}

/******************************************************************************************************/

struct PolKitPrivilege_s
{
};

PolKitPrivilege *
libpolkit_privilege_new (void)
{
        return NULL;
}

PolKitPrivilege *
libpolkit_privilege_ref (PolKitPrivilege *privilege)
{
        return privilege;
}

void
libpolkit_privilege_set_privilege_id (PolKitPrivilege *privilege, const char  *privilege_id)
{
}

gboolean
libpolkit_privilege_get_privilege_id (PolKitPrivilege *privilege, char **out_privilege_id)
{
        return FALSE;
}

void
libpolkit_privilege_unref (PolKitPrivilege *privilege)
{
}

/******************************************************************************************************/

struct PolKitResource_s
{
};

PolKitResource *
libpolkit_resource_new (void)
{
        return NULL;
}

PolKitResource *
libpolkit_resource_ref (PolKitResource *resource)
{
        return resource;
}

void
libpolkit_resource_set_resource_type (PolKitResource *resource, const char  *resource_type)
{
}

void
libpolkit_resource_set_resource_id (PolKitResource *resource, const char  *resource_id)
{
}

gboolean
libpolkit_resource_get_resource_type (PolKitResource *resource, char **out_resource_type)
{
        return FALSE;
}

gboolean 
libpolkit_resource_get_resource_id (PolKitResource *resource, char **out_resource_id)
{
        return FALSE;
}

void 
libpolkit_resource_unref (PolKitResource *resource)
{
}

/******************************************************************************************************/

struct PolKitSeat_s
{
};

PolKitSeat *
libpolkit_seat_new (void)
{
        return NULL;
}

PolKitSeat *
libpolkit_seat_ref (PolKitSeat *seat)
{
        return seat;
}

void 
libpolkit_seat_set_ck_objref (PolKitSeat *seat, const char *ck_objref)
{
}

gboolean
libpolkit_seat_get_ck_objref (PolKitSeat *seat, char **out_ck_objref)
{
        return FALSE;
}

void
libpolkit_seat_unref (PolKitSeat *seat)
{
}

/******************************************************************************************************/

struct PolKitSession_s
{
};

PolKitSession *
libpolkit_session_new (void)
{
        return NULL;
}

PolKitSession *
libpolkit_session_ref (PolKitSession *session)
{
        return NULL;
}

void 
libpolkit_session_set_uid (PolKitSession *session, uid_t uid)
{
}

void 
libpolkit_session_set_ck_objref (PolKitSession *session, const char *ck_objref)
{
}

void 
libpolkit_session_set_ck_is_active (PolKitSession *session, gboolean is_active)
{
}

void 
libpolkit_session_set_ck_is_local (PolKitSession *session, gboolean is_local)
{
}

void 
libpolkit_session_set_ck_remote_host (PolKitSession *session, const char *remote_host)
{
}

void 
libpolkit_session_set_ck_seat (PolKitSession *session, PolKitSeat *seat)
{
}

gboolean
libpolkit_session_get_uid (PolKitSession *session, uid_t *out_uid)
{
        return FALSE;
}

gboolean
libpolkit_session_get_ck_objref (PolKitSession *session, char **out_ck_objref)
{
        return FALSE;
}

gboolean
libpolkit_session_get_ck_is_active (PolKitSession *session, gboolean *out_is_active)
{
        return FALSE;
}

gboolean
libpolkit_session_get_ck_is_local (PolKitSession *session, gboolean *out_is_local)
{
        return FALSE;
}

gboolean
libpolkit_session_get_ck_remote_host (PolKitSession *session, char *out_remote_host)
{
        return FALSE;
}

gboolean
libpolkit_session_get_ck_seat (PolKitSession *session, PolKitSeat **out_seat)
{
        return FALSE;
}


void 
libpolkit_session_unref (PolKitSession *session)
{
}

/******************************************************************************************************/

struct PolKitCaller_s
{
};

PolKitCaller *
libpolkit_caller_new (void)
{
        return NULL;
}

PolKitCaller *
libpolkit_caller_ref (PolKitCaller *caller)
{
        return caller;
}

void
libpolkit_caller_set_dbus_name (PolKitCaller *caller, const char *dbus_name)
{
}

void
libpolkit_caller_set_uid (PolKitCaller *caller, uid_t uid)
{
}

void
libpolkit_caller_set_pid (PolKitCaller *caller, pid_t pid)
{
}

void
libpolkit_caller_set_selinux_context (PolKitCaller *caller, const char *selinux_context)
{
}

void
libpolkit_caller_set_ck_session (PolKitCaller *caller, PolKitSession *session)
{
}

gboolean
libpolkit_caller_get_dbus_name (PolKitCaller *caller, char **out_dbus_name)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_uid (PolKitCaller *caller, uid_t *out_uid)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_pid (PolKitCaller *caller, uid_t *out_pid)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_selinux_context (PolKitCaller *caller, char *out_selinux_context)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_ck_session (PolKitCaller *caller, PolKitSession **out_session)
{
        return FALSE;
}

void
libpolkit_caller_unref (PolKitCaller *caller)
{
}

/******************************************************************************************************/


/**
 * libpolkit_get_seat_resource_association:
 * @pk_context: the PolicyKit context
 * @visitor: visitor function
 * @user_data: user data
 *
 * Retrieve information about what resources are associated to what
 * seats. Note that a resource may be associated to more than one
 * seat. This information stems from user configuration and consumers
 * of this information that know better (e.g. HAL) may choose to
 * override it. 
 *
 * Typically, this information is used to e.g. bootstrap the system
 * insofar that it can be used to start login greeters on the given
 * video hardware (e.g. resources) on the given user-configured seats.
 */
void
libpolkit_get_seat_resource_association (PolKitContext       *pk_context,
                                         PolKitSeatVisitorCB  visitor,
                                         gpointer            *user_data)
{
}

/**
 * libpolkit_is_resource_associated_with_seat:
 * @pk_context: the PolicyKit context
 * @resource: the resource in question
 * @seat: the seat
 *
 * Determine if a given resource is associated with a given seat. The
 * same comments noted in libpolkit_get_seat_resource_association() about the
 * source purely being user configuration applies here as well.
 *
 * Returns: TRUE if, and only if, the given resource is
 * associated with the given seat.
 */
gboolean
libpolkit_is_resource_associated_with_seat (PolKitContext   *pk_context,
                                            PolKitResource  *resource,
                                            PolKitSeat      *seat)
{
        return FALSE;
}

/**
 * libpolkit_can_session_access_resource:
 * @pk_context: the PolicyKit context
 * @privilege: the type of access to check for
 * @resource: the resource in question
 * @session: the session in question
 *
 * Determine if a given session can access a given resource in a given way.
 *
 * Returns: TRUE if, and only if, the given session can access the
 * given resource in the given way.
 */
gboolean
libpolkit_can_session_access_resource (PolKitContext   *pk_context,
                                       PolKitPrivilege *privilege,
                                       PolKitResource  *resource,
                                       PolKitSession   *session)
{
        return FALSE;
}

/**
 * libpolkit_can_caller_access_resource:
 * @pk_context: the PolicyKit context
 * @privilege: the type of access to check for
 * @resource: the resource in question
 * @caller: the resource in question
 *
 * Determine if a given caller can access a given resource in a given way.
 *
 * Returns: TRUE if, and only if, the given caller can access the given interface
 * of the given resource in the given way.
 */

gboolean
libpolkit_can_caller_access_resource (PolKitContext   *pk_context,
                                      PolKitPrivilege *privilege,
                                      PolKitResource  *resource,
                                      PolKitCaller    *caller)
{
        return FALSE;
}


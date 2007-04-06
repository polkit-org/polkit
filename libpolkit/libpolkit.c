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

/**
 * SECTION:libpolkit
 * @short_description: Policy functions.
 *
 * These functions are used to query system policy.
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
#include "libpolkit.h"

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
 *
 * If a resource is not associated with any seat, it is assumed to be
 * available to any local seat.
 *
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW or
 * #LIBPOLKIT_RESULT_YES (if the callback was invoked)
 */
PolKitResult
libpolkit_get_seat_resource_association (PolKitContext       *pk_context,
                                         PolKitSeatVisitorCB  visitor,
                                         gpointer            *user_data)
{
        return LIBPOLKIT_RESULT_YES;
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
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
 * #LIBPOLKIT_RESULT_YES, #LIBPOLKIT_RESULT_NO.
 */
PolKitResult
libpolkit_is_resource_associated_with_seat (PolKitContext   *pk_context,
                                            PolKitResource  *resource,
                                            PolKitSeat      *seat)
{
        return LIBPOLKIT_RESULT_NO;
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
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
 * #LIBPOLKIT_RESULT_YES, #LIBPOLKIT_RESULT_NO.
 */
PolKitResult
libpolkit_can_session_access_resource (PolKitContext   *pk_context,
                                       PolKitPrivilege *privilege,
                                       PolKitResource  *resource,
                                       PolKitSession   *session)
{
        PolKitPrivilegeCache *cache;
        PolKitResult result;
        PolKitPrivilegeFileEntry *pfe;

        result = LIBPOLKIT_RESULT_NO;

        cache = libpolkit_context_get_privilege_cache (pk_context);
        if (cache == NULL)
                goto out;

        g_debug ("entering libpolkit_can_session_access_resource()");
        libpolkit_privilege_debug (privilege);
        libpolkit_resource_debug (resource);
        libpolkit_session_debug (session);

        pfe = libpolkit_privilege_cache_get_entry (cache, privilege);
        if (pfe == NULL) {
                char *privilege_name;
                if (!libpolkit_privilege_get_privilege_id (privilege, &privilege_name)) {
                        g_warning ("given privilege has no name");
                } else {
                        g_warning ("no privilege with name '%s'", privilege_name);
                }
                result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
                goto out;
        }

        libpolkit_privilege_file_entry_debug (pfe);
        
        /* for now, hardcode to defaults */
        result = libpolkit_privilege_default_can_session_access_resource (
                libpolkit_privilege_file_entry_get_default (pfe), 
                privilege, 
                resource, 
                session);
out:
        g_debug ("... result was %s", libpolkit_result_to_string_representation (result));
        return result;
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
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * access the resource in the given way
 */
PolKitResult
libpolkit_can_caller_access_resource (PolKitContext   *pk_context,
                                      PolKitPrivilege *privilege,
                                      PolKitResource  *resource,
                                      PolKitCaller    *caller)
{
        PolKitPrivilegeCache *cache;
        PolKitResult result;
        PolKitPrivilegeFileEntry *pfe;

        result = LIBPOLKIT_RESULT_NO;

        cache = libpolkit_context_get_privilege_cache (pk_context);
        if (cache == NULL)
                goto out;

        g_debug ("entering libpolkit_can_caller_access_resource()");
        libpolkit_privilege_debug (privilege);
        libpolkit_resource_debug (resource);
        libpolkit_caller_debug (caller);

        pfe = libpolkit_privilege_cache_get_entry (cache, privilege);
        if (pfe == NULL) {
                char *privilege_name;
                if (!libpolkit_privilege_get_privilege_id (privilege, &privilege_name)) {
                        g_warning ("given privilege has no name");
                } else {
                        g_warning ("no privilege with name '%s'", privilege_name);
                }
                result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
                goto out;
        }

        libpolkit_privilege_file_entry_debug (pfe);

        /* for now, hardcode to defaults */
        result = libpolkit_privilege_default_can_caller_access_resource (
                libpolkit_privilege_file_entry_get_default (pfe), 
                privilege, 
                resource, 
                caller);

out:
        g_debug ("... result was %s", libpolkit_result_to_string_representation (result));
        return result;
}

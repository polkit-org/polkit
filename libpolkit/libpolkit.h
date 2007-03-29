/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit.h : library for querying system-wide policy
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBPOLKIT_H
#define LIBPOLKIT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-context.h>
#include <libpolkit/libpolkit-privilege.h>
#include <libpolkit/libpolkit-resource.h>
#include <libpolkit/libpolkit-seat.h>
#include <libpolkit/libpolkit-session.h>
#include <libpolkit/libpolkit-caller.h>



/**
 * PolKitSeatVisitorCB:
 * @seat: the seat
 * @resources_associated_with_seat: A NULL terminated array of resources associated with the seat
 * @user_data: user data
 *
 * Visitor function for libpolkit_get_seat_resource_association(). The caller should _not_ unref the passed objects.
 *
 */
typedef void (*PolKitSeatVisitorCB) (PolKitSeat      *seat,
                                     PolKitResource **resources_associated_with_seat,
                                     gpointer         user_data);

void
libpolkit_get_seat_resource_association (PolKitContext       *pk_context,
                                         PolKitSeatVisitorCB  visitor,
                                         gpointer            *user_data);

gboolean
libpolkit_is_resource_associated_with_seat (PolKitContext   *pk_context,
                                            PolKitResource  *resource,
                                            PolKitSeat      *seat);

gboolean
libpolkit_can_session_access_resource (PolKitContext   *pk_context,
                                       PolKitPrivilege *privilege,
                                       PolKitResource  *resource,
                                       PolKitSession   *session);

gboolean
libpolkit_can_caller_access_resource (PolKitContext   *pk_context,
                                      PolKitPrivilege *privilege,
                                      PolKitResource  *resource,
                                      PolKitCaller    *caller);

#endif /* LIBPOLKIT_H */



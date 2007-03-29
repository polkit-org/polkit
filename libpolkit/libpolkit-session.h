/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-session.h : sessions
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

#ifndef LIBPOLKIT_SESSION_H
#define LIBPOLKIT_SESSION_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <dbus/dbus.h>

#include <libpolkit/libpolkit-seat.h>

struct PolKitSession;
typedef struct PolKitSession PolKitSession;

PolKitSession *libpolkit_session_new                (void);
PolKitSession *libpolkit_session_new_from_objpath   (DBusConnection *con, const char *objpath, uid_t uid, DBusError *error);
PolKitSession *libpolkit_session_new_from_cookie    (DBusConnection *con, const char *cookie, DBusError *error);
PolKitSession *libpolkit_session_ref                (PolKitSession *session);
void           libpolkit_session_unref              (PolKitSession *session);
void           libpolkit_session_set_uid            (PolKitSession *session, uid_t           uid);
void           libpolkit_session_set_seat           (PolKitSession *session, PolKitSeat     *seat);
void           libpolkit_session_set_ck_objref      (PolKitSession *session, const char     *ck_objref);
void           libpolkit_session_set_ck_is_active   (PolKitSession *session, gboolean        is_active);
void           libpolkit_session_set_ck_is_local    (PolKitSession *session, gboolean        is_local);
void           libpolkit_session_set_ck_remote_host (PolKitSession *session, const char     *remote_host);
gboolean       libpolkit_session_get_uid            (PolKitSession *session, uid_t          *out_uid);
gboolean       libpolkit_session_get_seat           (PolKitSession *session, PolKitSeat    **out_seat);
gboolean       libpolkit_session_get_ck_objref      (PolKitSession *session, char          **out_ck_objref);
gboolean       libpolkit_session_get_ck_is_active   (PolKitSession *session, gboolean       *out_is_active);
gboolean       libpolkit_session_get_ck_is_local    (PolKitSession *session, gboolean       *out_is_local);
gboolean       libpolkit_session_get_ck_remote_host (PolKitSession *session, char          **out_remote_host);

#endif /* LIBPOLKIT_SESSION_H */

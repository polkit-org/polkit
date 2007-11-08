/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-session.h : sessions
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_SESSION_H
#define POLKIT_SESSION_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-seat.h>

#include <sys/types.h>

POLKIT_BEGIN_DECLS

struct _PolKitSession;
typedef struct _PolKitSession PolKitSession;

PolKitSession *polkit_session_new                (void);
PolKitSession *polkit_session_ref                (PolKitSession *session);
void           polkit_session_unref              (PolKitSession *session);
polkit_bool_t  polkit_session_set_uid            (PolKitSession *session, uid_t           uid);
polkit_bool_t  polkit_session_set_seat           (PolKitSession *session, PolKitSeat     *seat);
polkit_bool_t  polkit_session_set_ck_objref      (PolKitSession *session, const char     *ck_objref);
polkit_bool_t  polkit_session_set_ck_is_active   (PolKitSession *session, polkit_bool_t   is_active);
polkit_bool_t  polkit_session_set_ck_is_local    (PolKitSession *session, polkit_bool_t   is_local);
polkit_bool_t  polkit_session_set_ck_remote_host (PolKitSession *session, const char     *remote_host);
polkit_bool_t  polkit_session_get_uid            (PolKitSession *session, uid_t          *out_uid);
polkit_bool_t  polkit_session_get_seat           (PolKitSession *session, PolKitSeat    **out_seat);
polkit_bool_t  polkit_session_get_ck_objref      (PolKitSession *session, char          **out_ck_objref);
polkit_bool_t  polkit_session_get_ck_is_active   (PolKitSession *session, polkit_bool_t  *out_is_active);
polkit_bool_t  polkit_session_get_ck_is_local    (PolKitSession *session, polkit_bool_t  *out_is_local);
polkit_bool_t  polkit_session_get_ck_remote_host (PolKitSession *session, char          **out_remote_host);

void           polkit_session_debug              (PolKitSession *session);
polkit_bool_t  polkit_session_validate           (PolKitSession *session);

POLKIT_END_DECLS

#endif /* POLKIT_SESSION_H */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-session.h : sessions
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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

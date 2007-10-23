/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-db.h : Represents the authorization database
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

#ifndef POLKIT_AUTHORIZATION_DB_H
#define POLKIT_AUTHORIZATION_DB_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-authorization.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-session.h>

POLKIT_BEGIN_DECLS

struct _PolKitAuthorizationDB;
typedef struct _PolKitAuthorizationDB PolKitAuthorizationDB;

PolKitAuthorizationDB *polkit_authorization_db_new            (void);
PolKitAuthorizationDB *polkit_authorization_db_ref            (PolKitAuthorizationDB *authdb);
void                   polkit_authorization_db_unref          (PolKitAuthorizationDB *authdb);

void                   polkit_authorization_db_debug          (PolKitAuthorizationDB *authdb);
polkit_bool_t          polkit_authorization_db_validate       (PolKitAuthorizationDB *authdb);


polkit_bool_t polkit_authorization_db_is_session_authorized (PolKitAuthorizationDB *authdb,
                                                             PolKitAction          *action,
                                                             PolKitSession         *session,
                                                             polkit_bool_t         *out_is_authorized);

polkit_bool_t polkit_authorization_db_is_caller_authorized (PolKitAuthorizationDB *authdb,
                                                            PolKitAction          *action,
                                                            PolKitCaller          *caller,
                                                            polkit_bool_t         *out_is_authorized);



polkit_bool_t polkit_authorization_db_add_entry_process          (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  PolKitCaller          *caller,
                                                                  PolKitResult           how,
                                                                  uid_t                  user_authenticated_as);

polkit_bool_t polkit_authorization_db_add_entry_session          (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  PolKitSession         *session,
                                                                  PolKitResult           how,
                                                                  uid_t                  user_authenticated_as);

polkit_bool_t polkit_authorization_db_add_entry_always           (PolKitAuthorizationDB *authdb,
                                                                  PolKitAction          *action,
                                                                  uid_t                  uid,
                                                                  PolKitResult           how,
                                                                  uid_t                  user_authenticated_as);


POLKIT_END_DECLS

#endif /* POLKIT_AUTHORIZATION_DB_H */



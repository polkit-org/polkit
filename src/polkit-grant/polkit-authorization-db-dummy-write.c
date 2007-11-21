/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-db.c : Dummy authorization database
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>

#include <glib.h>

#include <polkit/polkit-debug.h>
#include <polkit/polkit-authorization-db.h>
#include <polkit/polkit-utils.h>
#include <polkit/polkit-private.h>

/* PolKitAuthorizationDB structure is defined in polkit/polkit-private.h */

polkit_bool_t
polkit_authorization_db_add_entry_process_one_shot (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    PolKitCaller          *caller,
                                                    uid_t                  user_authenticated_as)
{
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_add_entry_process          (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    PolKitCaller          *caller,
                                                    uid_t                  user_authenticated_as)
{
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_add_entry_session          (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    PolKitCaller          *caller,
                                                    uid_t                  user_authenticated_as)
{
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_add_entry_always           (PolKitAuthorizationDB *authdb,
                                                    PolKitAction          *action,
                                                    PolKitCaller          *caller,
                                                    uid_t                  user_authenticated_as)
{
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_grant_to_uid           (PolKitAuthorizationDB          *authdb,
                                                PolKitAction                   *action,
                                                uid_t                           uid,
                                                PolKitAuthorizationConstraint  *constraint,
                                                PolKitError                   **error)
{
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_grant_negative_to_uid           (PolKitAuthorizationDB          *authdb,
                                                         PolKitAction                   *action,
                                                         uid_t                           uid,
                                                         PolKitAuthorizationConstraint  *constraint,
                                                         PolKitError                   **error)
{
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
        return FALSE;
}

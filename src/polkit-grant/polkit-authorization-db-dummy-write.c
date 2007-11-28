/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-db.c : Dummy authorization database
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

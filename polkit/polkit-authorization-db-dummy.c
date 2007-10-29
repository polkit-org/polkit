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

#include "polkit-debug.h"
#include "polkit-authorization-db.h"
#include "polkit-utils.h"
#include "polkit-private.h"

struct _PolKitAuthorizationDB
{
        int refcount;
};

PolKitAuthorizationDBCapability
polkit_authorization_db_get_capabilities (void)
{
        return 0;
}

PolKitAuthorizationDB *
_polkit_authorization_db_new (void)
{
        PolKitAuthorizationDB *authdb;

        authdb = g_new0 (PolKitAuthorizationDB, 1);
        authdb->refcount = 1;

        return authdb;
}

void
_polkit_authorization_db_pfe_foreach   (PolKitPolicyCache *policy_cache, 
                                        PolKitPolicyCacheForeachFunc callback,
                                        void *user_data)
{
}

PolKitPolicyFileEntry* 
_polkit_authorization_db_pfe_get_by_id (PolKitPolicyCache *policy_cache, 
                                        const char *action_id)
{
        return NULL;
}

PolKitAuthorizationDB *
polkit_authorization_db_ref (PolKitAuthorizationDB *authdb)
{
        g_return_val_if_fail (authdb != NULL, authdb);
        authdb->refcount++;
        return authdb;
}

void 
polkit_authorization_db_unref (PolKitAuthorizationDB *authdb)
{
        g_return_if_fail (authdb != NULL);
        authdb->refcount--;
        if (authdb->refcount > 0) 
                return;
        g_free (authdb);
}

void 
polkit_authorization_db_debug (PolKitAuthorizationDB *authdb)
{
        g_return_if_fail (authdb != NULL);
        _pk_debug ("PolKitAuthorizationDB: refcount=%d", authdb->refcount);
}

polkit_bool_t
polkit_authorization_db_validate (PolKitAuthorizationDB *authdb)
{
        g_return_val_if_fail (authdb != NULL, FALSE);

        return TRUE;
}

void
_polkit_authorization_db_invalidate_cache (PolKitAuthorizationDB *authdb)
{
}

polkit_bool_t 
polkit_authorization_db_is_session_authorized (PolKitAuthorizationDB *authdb,
                                               PolKitAction          *action,
                                               PolKitSession         *session,
                                               polkit_bool_t         *out_is_authorized)
{
        *out_is_authorized = FALSE;
        return TRUE;
}

polkit_bool_t
polkit_authorization_db_is_caller_authorized (PolKitAuthorizationDB *authdb,
                                              PolKitAction          *action,
                                              PolKitCaller          *caller,
                                              polkit_bool_t         *out_is_authorized)
{
        *out_is_authorized = FALSE;
        return TRUE;
}


polkit_bool_t
polkit_authorization_db_foreach (PolKitAuthorizationDB       *authdb,
                                 PolKitAuthorizationDBForeach cb,
                                 void                        *user_data,
                                 PolKitError                **error)
{
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_foreach_for_uid (PolKitAuthorizationDB       *authdb,
                                         uid_t                        uid,
                                         PolKitAuthorizationDBForeach cb,
                                         void                        *user_data,
                                         PolKitError                **error)
{
        return FALSE;
}

polkit_bool_t 
polkit_authorization_db_foreach_for_action (PolKitAuthorizationDB       *authdb,
                                            PolKitAction                *action,
                                            PolKitAuthorizationDBForeach cb,
                                            void                        *user_data,
                                            PolKitError                **error)
{
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_foreach_for_action_for_uid (PolKitAuthorizationDB       *authdb,
                                                    PolKitAction                *action,
                                                    uid_t                        uid,
                                                    PolKitAuthorizationDBForeach cb,
                                                    void                        *user_data,
                                                    PolKitError                **error)
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
polkit_authorization_db_revoke_entry (PolKitAuthorizationDB *authdb,
                                      PolKitAuthorization *auth,
                                      PolKitError **error)
{
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
        return FALSE;
}



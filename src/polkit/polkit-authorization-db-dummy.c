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

#include "polkit-debug.h"
#include "polkit-authorization-db.h"
#include "polkit-utils.h"
#include "polkit-private.h"
#include "polkit-test.h"

/* PolKitAuthorizationDB structure is defined in polkit/polkit-private.h */

PolKitAuthorizationDBCapability
polkit_authorization_db_get_capabilities (void)
{
        return 0;
}

PolKitAuthorizationDB *
_polkit_authorization_db_new (void)
{
        PolKitAuthorizationDB *authdb;

        authdb = kit_new0 (PolKitAuthorizationDB, 1);
        authdb->refcount = 1;

        return authdb;
}

polkit_bool_t
_polkit_authorization_db_pfe_foreach   (PolKitPolicyCache *policy_cache, 
                                        PolKitPolicyCacheForeachFunc callback,
                                        void *user_data)
{
        return FALSE;
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
        kit_return_val_if_fail (authdb != NULL, authdb);
        authdb->refcount++;
        return authdb;
}

void 
polkit_authorization_db_unref (PolKitAuthorizationDB *authdb)
{
        kit_return_if_fail (authdb != NULL);
        authdb->refcount--;
        if (authdb->refcount > 0) 
                return;
        kit_free (authdb);
}

void 
polkit_authorization_db_debug (PolKitAuthorizationDB *authdb)
{
        kit_return_if_fail (authdb != NULL);
        _pk_debug ("PolKitAuthorizationDB: refcount=%d", authdb->refcount);
}

polkit_bool_t
polkit_authorization_db_validate (PolKitAuthorizationDB *authdb)
{
        kit_return_val_if_fail (authdb != NULL, FALSE);

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
                                               polkit_bool_t         *out_is_authorized,
                                               polkit_bool_t         *out_is_negative_authorized,
                                               PolKitError          **error)
{
        *out_is_authorized = FALSE;
        *out_is_negative_authorized = FALSE;
        return TRUE;
}

polkit_bool_t
polkit_authorization_db_is_caller_authorized (PolKitAuthorizationDB *authdb,
                                              PolKitAction          *action,
                                              PolKitCaller          *caller,
                                              polkit_bool_t          revoke_if_one_shot,
                                              polkit_bool_t         *out_is_authorized,
                                              polkit_bool_t         *out_is_negative_authorized,
                                              PolKitError          **error)
{
        *out_is_authorized = FALSE;
        *out_is_negative_authorized = FALSE;
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
polkit_authorization_db_revoke_entry (PolKitAuthorizationDB *authdb,
                                      PolKitAuthorization *auth,
                                      PolKitError **error)
{
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
        return FALSE;
}

polkit_bool_t
polkit_authorization_db_is_uid_blocked_by_self (PolKitAuthorizationDB *authdb,
                                                PolKitAction          *action,
                                                uid_t                  uid,
                                                PolKitError          **error)
{
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
        return FALSE;
}


#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_authorization_db = {
        "polkit_authorization_db",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

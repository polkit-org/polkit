/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-implicit-authorization.c : policy definition for the defaults
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
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include "polkit-debug.h"
#include "polkit-error.h"
#include "polkit-implicit-authorization.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-implicit-authorization
 * @title: Defaults
 * @short_description: Models the default policy for an action.
 *
 * This class records the default policy of an action.
 **/

/**
 * PolKitImplicitAuthorization:
 *
 * Objects of this class are used to record information about a
 * default policy for an action.
 **/
struct _PolKitImplicitAuthorization
{
        int refcount;
        PolKitResult default_any;
        PolKitResult default_inactive;
        PolKitResult default_active;
};

/**
 * polkit_implicit_authorization_new:
 *
 * Construct a new object with all defaults set as restrictive as possible.
 *
 * Returns: a new object or #NULL on OOM.
 *
 * Since: 0.7
 */
PolKitImplicitAuthorization *
polkit_implicit_authorization_new (void)
{
        PolKitImplicitAuthorization *pd;

        pd = kit_new0 (PolKitImplicitAuthorization, 1);
        if (pd == NULL)
                goto out;
        pd->refcount = 1;
        pd->default_any = POLKIT_RESULT_NO;
        pd->default_inactive = POLKIT_RESULT_NO;
        pd->default_active = POLKIT_RESULT_NO;
out:
        return pd;
}

/**
 * polkit_implicit_authorization_clone:
 * @implicit_authorization: object to clone
 *
 * Create a new object with the same value as the given object
 *
 * Returns: a new object or #NULL on OOM.
 *
 * Since: 0.7
 */
PolKitImplicitAuthorization *
polkit_implicit_authorization_clone (PolKitImplicitAuthorization *implicit_authorization)
{
        PolKitImplicitAuthorization *pd;

        kit_return_val_if_fail (implicit_authorization != NULL, NULL);

        pd = polkit_implicit_authorization_new ();
        if (pd == NULL)
                goto out;
        pd->refcount = 1;
        pd->default_any      = implicit_authorization->default_any;
        pd->default_inactive = implicit_authorization->default_inactive;
        pd->default_active   = implicit_authorization->default_active;
out:
        return pd;
}


/**
 * polkit_implicit_authorization_equals:
 * @a: a #PolKitImplicitAuthorization object
 * @b: a #PolKitImplicitAuthorization object
 *
 * Compare if two objects are equal.
 *
 * Returns: %TRUE only if the objects are equal
 */
polkit_bool_t
polkit_implicit_authorization_equals (PolKitImplicitAuthorization *a, PolKitImplicitAuthorization *b)
{
        polkit_bool_t ret;

        kit_return_val_if_fail (a != NULL, FALSE);
        kit_return_val_if_fail (b != NULL, FALSE);

        if (a->default_any      == b->default_any &&
            a->default_inactive == b->default_inactive &&
            a->default_active   == b->default_active) {
                ret = TRUE;
        } else {
                ret = FALSE;
        }

        return ret;
}

PolKitImplicitAuthorization *
_polkit_implicit_authorization_new (PolKitResult defaults_allow_any,
                            PolKitResult defaults_allow_inactive,
                            PolKitResult defaults_allow_active)
{
        PolKitImplicitAuthorization *pd;

        pd = kit_new0 (PolKitImplicitAuthorization, 1);
        if (pd == NULL)
                goto out;
        pd->refcount = 1;
        pd->default_any = defaults_allow_any;
        pd->default_inactive = defaults_allow_inactive;
        pd->default_active = defaults_allow_active;
out:
        return pd;
}

/**
 * polkit_implicit_authorization_ref:
 * @implicit_authorization: the policy object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitImplicitAuthorization *
polkit_implicit_authorization_ref (PolKitImplicitAuthorization *implicit_authorization)
{
        kit_return_val_if_fail (implicit_authorization != NULL, implicit_authorization);
        implicit_authorization->refcount++;
        return implicit_authorization;
}

/**
 * polkit_implicit_authorization_unref:
 * @implicit_authorization: the object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_implicit_authorization_unref (PolKitImplicitAuthorization *implicit_authorization)
{
        kit_return_if_fail (implicit_authorization != NULL);
        implicit_authorization->refcount--;
        if (implicit_authorization->refcount > 0) 
                return;
        kit_free (implicit_authorization);
}

/**
 * polkit_implicit_authorization_debug:
 * @implicit_authorization: the object
 * 
 * Print debug details
 **/
void
polkit_implicit_authorization_debug (PolKitImplicitAuthorization *implicit_authorization)
{
        kit_return_if_fail (implicit_authorization != NULL);
        polkit_debug ("PolKitImplicitAuthorization: refcount=%d\n"
                      "        default_any=%s\n"
                      "   default_inactive=%s\n"
                      "     default_active=%s", 
                      implicit_authorization->refcount,
                      polkit_result_to_string_representation (implicit_authorization->default_any),
                      polkit_result_to_string_representation (implicit_authorization->default_inactive),
                      polkit_result_to_string_representation (implicit_authorization->default_active));
}


/**
 * polkit_implicit_authorization_can_session_do_action:
 * @implicit_authorization: the object
 * @action: the type of access to check for
 * @session: the session in question
 * 
 * Using the default policy for an action, determine if a given
 * session can do a given action.
 * 
 * Returns: A #PolKitResult - can only be one of
 * #POLKIT_RESULT_YES, #POLKIT_RESULT_NO.
 **/
PolKitResult
polkit_implicit_authorization_can_session_do_action (PolKitImplicitAuthorization *implicit_authorization,
                                             PolKitAction        *action,
                                             PolKitSession       *session)
{
        polkit_bool_t is_local;
        polkit_bool_t is_active;
        PolKitResult ret;

        ret = POLKIT_RESULT_NO;

        kit_return_val_if_fail (implicit_authorization != NULL, ret);
        kit_return_val_if_fail (action != NULL, ret);
        kit_return_val_if_fail (session != NULL, ret);

        ret = implicit_authorization->default_any;

        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (!is_local)
                goto out;

        if (is_active) {
                ret = implicit_authorization->default_active;
        } else {
                ret = implicit_authorization->default_inactive;
        }
out:
        return ret;
}

/**
 * polkit_implicit_authorization_can_caller_do_action:
 * @implicit_authorization: the object
 * @action: the type of access to check for
 * @caller: the caller in question
 * 
 * Using the default policy for an action, determine if a given
 * caller can do a given action.
 * 
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do the given action.
 **/
PolKitResult
polkit_implicit_authorization_can_caller_do_action (PolKitImplicitAuthorization *implicit_authorization,
                                            PolKitAction        *action,
                                            PolKitCaller        *caller)
{
        polkit_bool_t is_local;
        polkit_bool_t is_active;
        PolKitSession *session;
        PolKitResult ret;

        ret = POLKIT_RESULT_NO;

        kit_return_val_if_fail (implicit_authorization != NULL, ret);
        kit_return_val_if_fail (action != NULL, ret);
        kit_return_val_if_fail (caller != NULL, ret);

        ret = implicit_authorization->default_any;

        polkit_caller_get_ck_session (caller, &session);
        if (session == NULL)
                goto out;

        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (!is_local)
                goto out;

        if (is_active) {
                ret = implicit_authorization->default_active;
        } else {
                ret = implicit_authorization->default_inactive;
        }

out:
        return ret;
}

/**
 * polkit_implicit_authorization_set_allow_any:
 * @implicit_authorization: the object
 * @value: the value to set
 * 
 * Set default policy.
 *
 **/
void
polkit_implicit_authorization_set_allow_any (PolKitImplicitAuthorization *implicit_authorization, PolKitResult value)
{
        kit_return_if_fail (implicit_authorization != NULL);
        implicit_authorization->default_any = value;
}

/**
 * polkit_implicit_authorization_set_allow_inactive:
 * @implicit_authorization: the object
 * @value: the value to set
 * 
 * Set default policy.
 *
 **/
void
polkit_implicit_authorization_set_allow_inactive (PolKitImplicitAuthorization *implicit_authorization, PolKitResult value)
{
        kit_return_if_fail (implicit_authorization != NULL);
        implicit_authorization->default_inactive = value;
}

/**
 * polkit_implicit_authorization_set_allow_active:
 * @implicit_authorization: the object
 * @value: the value to set
 * 
 * Set default policy.
 *
 **/
void
polkit_implicit_authorization_set_allow_active (PolKitImplicitAuthorization *implicit_authorization, PolKitResult value)
{
        kit_return_if_fail (implicit_authorization != NULL);
        implicit_authorization->default_active = value;
}

/**
 * polkit_implicit_authorization_get_allow_any:
 * @implicit_authorization: the object
 * 
 * Get default policy.
 * 
 * Returns: default policy
 **/
PolKitResult
polkit_implicit_authorization_get_allow_any (PolKitImplicitAuthorization *implicit_authorization)
{
        kit_return_val_if_fail (implicit_authorization != NULL, POLKIT_RESULT_NO);
        return implicit_authorization->default_any;
}

/**
 * polkit_implicit_authorization_get_allow_inactive:
 * @implicit_authorization: the object
 * 
 * Get default policy.
 * 
 * Returns: default policy
 **/
PolKitResult
polkit_implicit_authorization_get_allow_inactive (PolKitImplicitAuthorization *implicit_authorization)
{
        kit_return_val_if_fail (implicit_authorization != NULL, POLKIT_RESULT_NO);
        return implicit_authorization->default_inactive;
}

/**
 * polkit_implicit_authorization_get_allow_active:
 * @implicit_authorization: the object
 * 
 * Get default policy.
 * 
 * Returns: default policy
 **/
PolKitResult
polkit_implicit_authorization_get_allow_active (PolKitImplicitAuthorization *implicit_authorization)
{
        kit_return_val_if_fail (implicit_authorization != NULL, POLKIT_RESULT_NO);
        return implicit_authorization->default_active;
}


#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_ts (PolKitSession *s, PolKitResult any, PolKitResult inactive, PolKitResult active, PolKitResult *ret)
{
        PolKitAction *a;
        PolKitImplicitAuthorization *d;
        polkit_bool_t oom;

        oom = TRUE;

        if (s == NULL)
                goto out;

        if ((a = polkit_action_new ()) != NULL) {
                if (polkit_action_set_action_id (a, "org.dummy")) {
                        if ((d = _polkit_implicit_authorization_new (any,
                                                             inactive,
                                                             active)) != NULL) {
                                PolKitCaller *c;

                                *ret = polkit_implicit_authorization_can_session_do_action (d, a, s);
                                oom = FALSE;

                                if ((c = polkit_caller_new ()) != NULL) {
                                        kit_assert (polkit_implicit_authorization_can_caller_do_action (d, a, c) == any);

                                        kit_assert (polkit_caller_set_ck_session (c, s));
                                        kit_assert (polkit_implicit_authorization_can_caller_do_action (d, a, c) == *ret);
                                        polkit_caller_unref (c);
                                }

                                polkit_implicit_authorization_ref (d);
                                polkit_implicit_authorization_get_allow_any (d);
                                polkit_implicit_authorization_get_allow_inactive (d);
                                polkit_implicit_authorization_get_allow_active (d);
                                polkit_implicit_authorization_unref (d);
                                polkit_implicit_authorization_debug (d);
                                polkit_implicit_authorization_unref (d);
                        }
                }
                polkit_action_unref (a);
        }

out:
        return oom;
}

static polkit_bool_t
_run_test (void)
{
        PolKitResult ret;
        PolKitSession *s_active;
        PolKitSession *s_inactive;
        PolKitSession *s_active_remote;
        PolKitSession *s_inactive_remote;

        if ((s_active = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_active, "/session1")) {
                        polkit_session_unref (s_active);
                        s_active = NULL;
                } else {
                        kit_assert (polkit_session_set_ck_is_local (s_active, TRUE));
                        kit_assert (polkit_session_set_ck_is_active (s_active, TRUE));
                }
        }

        if ((s_inactive = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_inactive, "/session2")) {
                        polkit_session_unref (s_inactive);
                        s_inactive = NULL;
                } else {
                        kit_assert (polkit_session_set_ck_is_local (s_inactive, TRUE));
                        kit_assert (polkit_session_set_ck_is_active (s_inactive, FALSE));
                }
        }

        if ((s_active_remote = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_active_remote, "/session3") ||
                    !polkit_session_set_ck_remote_host (s_active_remote, "remotehost.com")) {
                        polkit_session_unref (s_active_remote);
                        s_active_remote = NULL;
                } else {
                        kit_assert (polkit_session_set_ck_is_local (s_active_remote, FALSE));
                        kit_assert (polkit_session_set_ck_is_active (s_active_remote, TRUE));
                }
        }

        if ((s_inactive_remote = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_inactive_remote, "/session4") ||
                    !polkit_session_set_ck_remote_host (s_inactive_remote, "remotehost.com")) {
                        polkit_session_unref (s_inactive_remote);
                        s_inactive_remote = NULL;
                } else {
                        kit_assert (polkit_session_set_ck_is_local (s_inactive_remote, FALSE));
                        kit_assert (polkit_session_set_ck_is_active (s_inactive_remote, FALSE));
                }
        }

        kit_assert (_ts (s_active, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        kit_assert (_ts (s_inactive, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);
        kit_assert (_ts (s_active_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);
        kit_assert (_ts (s_inactive_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);

        kit_assert (_ts (s_active, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        kit_assert (_ts (s_inactive, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        kit_assert (_ts (s_active_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);
        kit_assert (_ts (s_inactive_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);

        kit_assert (_ts (s_active, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        kit_assert (_ts (s_inactive, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        kit_assert (_ts (s_active_remote, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        kit_assert (_ts (s_inactive_remote, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);

        if (s_active != NULL)
                polkit_session_unref (s_active);

        if (s_inactive != NULL)
                polkit_session_unref (s_inactive);

        if (s_active_remote != NULL)
                polkit_session_unref (s_active_remote);

        if (s_inactive_remote != NULL)
                polkit_session_unref (s_inactive_remote);

        return TRUE;
}

KitTest _test_implicit_authorization = {
        "polkit_implicit_authorization",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

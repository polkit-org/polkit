/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-default.c : policy definition for the defaults
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
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "polkit-debug.h"
#include "polkit-error.h"
#include "polkit-policy-default.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-memory.h"

/**
 * SECTION:polkit-policy-default
 * @title: Defaults
 * @short_description: Models the default policy for an action.
 *
 * This class records the default policy of an action.
 **/

/**
 * PolKitPolicyDefault:
 *
 * Objects of this class are used to record information about a
 * default policy for an action.
 **/
struct _PolKitPolicyDefault
{
        int refcount;
        PolKitResult default_any;
        PolKitResult default_inactive;
        PolKitResult default_active;
};

PolKitPolicyDefault *
_polkit_policy_default_new (PolKitResult defaults_allow_any,
                            PolKitResult defaults_allow_inactive,
                            PolKitResult defaults_allow_active)
{
        PolKitPolicyDefault *pd;

        pd = p_new0 (PolKitPolicyDefault, 1);
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
 * polkit_policy_default_ref:
 * @policy_default: the policy object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyDefault *
polkit_policy_default_ref (PolKitPolicyDefault *policy_default)
{
        g_return_val_if_fail (policy_default != NULL, policy_default);
        policy_default->refcount++;
        return policy_default;
}

/**
 * polkit_policy_default_unref:
 * @policy_default: the object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_policy_default_unref (PolKitPolicyDefault *policy_default)
{
        g_return_if_fail (policy_default != NULL);
        policy_default->refcount--;
        if (policy_default->refcount > 0) 
                return;
        p_free (policy_default);
}

/**
 * polkit_policy_default_debug:
 * @policy_default: the object
 * 
 * Print debug details
 **/
void
polkit_policy_default_debug (PolKitPolicyDefault *policy_default)
{
        g_return_if_fail (policy_default != NULL);
        _pk_debug ("PolKitPolicyDefault: refcount=%d\n"
                   "        default_any=%s\n"
                   "   default_inactive=%s\n"
                   "     default_active=%s", 
                   policy_default->refcount,
                   polkit_result_to_string_representation (policy_default->default_any),
                   polkit_result_to_string_representation (policy_default->default_inactive),
                   polkit_result_to_string_representation (policy_default->default_active));
}


/**
 * polkit_policy_default_can_session_do_action:
 * @policy_default: the object
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
polkit_policy_default_can_session_do_action (PolKitPolicyDefault *policy_default,
                                             PolKitAction        *action,
                                             PolKitSession       *session)
{
        polkit_bool_t is_local;
        polkit_bool_t is_active;
        PolKitResult ret;

        ret = POLKIT_RESULT_NO;

        g_return_val_if_fail (policy_default != NULL, ret);
        g_return_val_if_fail (action != NULL, ret);
        g_return_val_if_fail (session != NULL, ret);

        ret = policy_default->default_any;

        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (!is_local)
                goto out;

        if (is_active) {
                ret = policy_default->default_active;
        } else {
                ret = policy_default->default_inactive;
        }
out:
        return ret;
}

/**
 * polkit_policy_default_can_caller_do_action:
 * @policy_default: the object
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
polkit_policy_default_can_caller_do_action (PolKitPolicyDefault *policy_default,
                                            PolKitAction        *action,
                                            PolKitCaller        *caller)
{
        polkit_bool_t is_local;
        polkit_bool_t is_active;
        PolKitSession *session;
        PolKitResult ret;

        ret = POLKIT_RESULT_NO;

        g_return_val_if_fail (policy_default != NULL, ret);
        g_return_val_if_fail (action != NULL, ret);
        g_return_val_if_fail (caller != NULL, ret);

        ret = policy_default->default_any;

        polkit_caller_get_ck_session (caller, &session);
        if (session == NULL)
                goto out;

        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (!is_local)
                goto out;

        if (is_active) {
                ret = policy_default->default_active;
        } else {
                ret = policy_default->default_inactive;
        }

out:
        return ret;
}

/**
 * polkit_policy_default_get_allow_any:
 * @policy_default: the object
 * 
 * Get default policy.
 * 
 * Returns: default policy
 **/
PolKitResult
polkit_policy_default_get_allow_any (PolKitPolicyDefault *policy_default)
{
        g_return_val_if_fail (policy_default != NULL, POLKIT_RESULT_NO);
        return policy_default->default_any;
}

/**
 * polkit_policy_default_get_allow_inactive:
 * @policy_default: the object
 * 
 * Get default policy.
 * 
 * Returns: default policy
 **/
PolKitResult
polkit_policy_default_get_allow_inactive (PolKitPolicyDefault *policy_default)
{
        g_return_val_if_fail (policy_default != NULL, POLKIT_RESULT_NO);
        return policy_default->default_inactive;
}

/**
 * polkit_policy_default_get_allow_active:
 * @policy_default: the object
 * 
 * Get default policy.
 * 
 * Returns: default policy
 **/
PolKitResult
polkit_policy_default_get_allow_active (PolKitPolicyDefault *policy_default)
{
        g_return_val_if_fail (policy_default != NULL, POLKIT_RESULT_NO);
        return policy_default->default_active;
}


#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_ts (PolKitSession *s, PolKitResult any, PolKitResult inactive, PolKitResult active, PolKitResult *ret)
{
        PolKitAction *a;
        PolKitPolicyDefault *d;
        polkit_bool_t oom;

        oom = TRUE;

        if (s == NULL)
                goto out;

        if ((a = polkit_action_new ()) != NULL) {
                if (polkit_action_set_action_id (a, "org.dummy")) {
                        if ((d = _polkit_policy_default_new (any,
                                                             inactive,
                                                             active)) != NULL) {
                                PolKitCaller *c;

                                *ret = polkit_policy_default_can_session_do_action (d, a, s);
                                oom = FALSE;

                                if ((c = polkit_caller_new ()) != NULL) {
                                        g_assert (polkit_policy_default_can_caller_do_action (d, a, c) == any);

                                        g_assert (polkit_caller_set_ck_session (c, s));
                                        g_assert (polkit_policy_default_can_caller_do_action (d, a, c) == *ret);
                                        polkit_caller_unref (c);
                                }

                                polkit_policy_default_ref (d);
                                polkit_policy_default_get_allow_any (d);
                                polkit_policy_default_get_allow_inactive (d);
                                polkit_policy_default_get_allow_active (d);
                                polkit_policy_default_unref (d);
                                polkit_policy_default_debug (d);
                                polkit_policy_default_unref (d);
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
                        g_assert (polkit_session_set_ck_is_local (s_active, TRUE));
                        g_assert (polkit_session_set_ck_is_active (s_active, TRUE));
                }
        }

        if ((s_inactive = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_inactive, "/session2")) {
                        polkit_session_unref (s_inactive);
                        s_inactive = NULL;
                } else {
                        g_assert (polkit_session_set_ck_is_local (s_inactive, TRUE));
                        g_assert (polkit_session_set_ck_is_active (s_inactive, FALSE));
                }
        }

        if ((s_active_remote = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_active_remote, "/session3") ||
                    !polkit_session_set_ck_remote_host (s_active_remote, "remotehost.com")) {
                        polkit_session_unref (s_active_remote);
                        s_active_remote = NULL;
                } else {
                        g_assert (polkit_session_set_ck_is_local (s_active_remote, FALSE));
                        g_assert (polkit_session_set_ck_is_active (s_active_remote, TRUE));
                }
        }

        if ((s_inactive_remote = polkit_session_new ()) != NULL) {
                if (!polkit_session_set_ck_objref (s_inactive_remote, "/session4") ||
                    !polkit_session_set_ck_remote_host (s_inactive_remote, "remotehost.com")) {
                        polkit_session_unref (s_inactive_remote);
                        s_inactive_remote = NULL;
                } else {
                        g_assert (polkit_session_set_ck_is_local (s_inactive_remote, FALSE));
                        g_assert (polkit_session_set_ck_is_active (s_inactive_remote, FALSE));
                }
        }

        g_assert (_ts (s_active, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        g_assert (_ts (s_inactive, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);
        g_assert (_ts (s_active_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);
        g_assert (_ts (s_inactive_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_NO, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);

        g_assert (_ts (s_active, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        g_assert (_ts (s_inactive, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        g_assert (_ts (s_active_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);
        g_assert (_ts (s_inactive_remote, 
                       POLKIT_RESULT_NO, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_NO);

        g_assert (_ts (s_active, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        g_assert (_ts (s_inactive, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        g_assert (_ts (s_active_remote, 
                       POLKIT_RESULT_YES, POLKIT_RESULT_YES, POLKIT_RESULT_YES, &ret) || 
                  ret == POLKIT_RESULT_YES);
        g_assert (_ts (s_inactive_remote, 
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

PolKitTest _test_policy_default = {
        "polkit_policy_default",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

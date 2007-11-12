/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-constraint.c : Conditions that must be
 * satisfied in order for an authorization to apply
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

#include "polkit-debug.h"
#include "polkit-authorization-constraint.h"
#include "polkit-utils.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-private.h"
 
/**
 * SECTION:polkit-authorization-constraint
 * @title: Authorization Constraints
 * @short_description: Conditions that must be satisfied in
 * order for an authorization to apply
 *
 * This class is used to represent conditions that must be satisfied
 * in order for an authorization to apply
 *
 * Since: 0.7
 **/

/**
 * PolKitAuthorizationConstraint:
 *
 * Instances of this class are used to represent conditions that must
 * be satisfied in order for an authorization to apply.
 *
 * Since: 0.7
 **/
struct _PolKitAuthorizationConstraint
{
        int refcount;
        PolKitAuthorizationConstraintFlags flags;
};

static PolKitAuthorizationConstraint _null_constraint = {-1, 0};

static PolKitAuthorizationConstraint _local_constraint = {-1, 
                                                          POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL};

static PolKitAuthorizationConstraint _active_constraint = {-1, 
                                                          POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE};

static PolKitAuthorizationConstraint _local_active_constraint = {-1, 
                                                                 POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL |
                                                                 POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE};

PolKitAuthorizationConstraint *
_polkit_authorization_constraint_new (const char *entry_in_auth_file)
{
        PolKitAuthorizationConstraint *authc;
        authc = kit_new0 (PolKitAuthorizationConstraint, 1);
        if (authc == NULL)
                goto oom;
        authc->refcount = 1;
oom:
        return authc;
}

/**
 * polkit_authorization_constraint_ref:
 * @authc: the object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 *
 * Since: 0.7
 **/
PolKitAuthorizationConstraint *
polkit_authorization_constraint_ref (PolKitAuthorizationConstraint *authc)
{
        kit_return_val_if_fail (authc != NULL, authc);
        if (authc->refcount == -1)
                return authc;
        authc->refcount++;
        return authc;
}

/**
 * polkit_authorization_constraint_unref:
 * @authc: the authorization_constraint object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 *
 * Since: 0.7
 **/
void
polkit_authorization_constraint_unref (PolKitAuthorizationConstraint *authc)
{
        kit_return_if_fail (authc != NULL);
        if (authc->refcount == -1)
                return;
        authc->refcount--;
        if (authc->refcount > 0) 
                return;

        kit_free (authc);
}

/**
 * polkit_authorization_constraint_debug:
 * @authc: the object
 * 
 * Print debug details
 *
 * Since: 0.7
 **/
void
polkit_authorization_constraint_debug (PolKitAuthorizationConstraint *authc)
{
        kit_return_if_fail (authc != NULL);
        _pk_debug ("PolKitAuthorizationConstraint: refcount=%d", authc->refcount);
}

/**
 * polkit_authorization_constraint_validate:
 * @authc: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 *
 * Since: 0.7
 **/
polkit_bool_t
polkit_authorization_constraint_validate (PolKitAuthorizationConstraint *authc)
{
        kit_return_val_if_fail (authc != NULL, FALSE);

        return TRUE;
}

/**
 * polkit_authorization_constraint_check_session:
 * @authc: the object
 * @session: the session
 *
 * Determine if the given session satisfies the conditions imposed by
 * the given constraint
 *
 * Returns: #TRUE if, and only if, the given session satisfies the
 * conditions imposed by the given constraint.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_constraint_check_session (PolKitAuthorizationConstraint *authc,
                                               PolKitSession                 *session)
{
        polkit_bool_t ret;
        polkit_bool_t is_active;
        polkit_bool_t is_local;

        kit_return_val_if_fail (authc != NULL, FALSE);
        kit_return_val_if_fail (session != NULL, FALSE);

        ret = FALSE;

        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (authc->flags & POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL)  {
                if (!is_local)
                        goto out;
        }

        if (authc->flags & POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE)  {
                if (!is_active)
                        goto out;
        }

        ret = TRUE;
out:
        return ret;
}

/**
 * polkit_authorization_constraint_check_caller:
 * @authc: the object
 * @caller: the caller
 *
 * Determine if the given caller satisfies the conditions imposed by
 * the given constraint
 *
 * Returns: #TRUE if, and only if, the given caller satisfies the
 * conditions imposed by the given constraint.
 *
 * Since: 0.7
 */
polkit_bool_t 
polkit_authorization_constraint_check_caller (PolKitAuthorizationConstraint *authc,
                                              PolKitCaller                  *caller)
{
        polkit_bool_t ret;
        PolKitSession *session;

        kit_return_val_if_fail (authc != NULL, FALSE);
        kit_return_val_if_fail (caller != NULL, FALSE);

        ret = FALSE;

        /* caller may not be in a session */
        if (polkit_caller_get_ck_session (caller, &session) && session != NULL) {
                ret = polkit_authorization_constraint_check_session (authc, session);
        } else {
                if (authc->flags == 0) {
                        ret = TRUE;
                }
        }

        return ret;
}

/**
 * polkit_authorization_constraint_get_flags:
 * @authc: the object
 *
 * Describe the constraint; this is only useful when inspecting an
 * authorization to present information to the user (e.g. as
 * polkit-auth(1) does).
 *
 * Note that the flags returned may not fully describe the constraint
 * and shouldn't be used to perform checking against #PolKitCaller or
 * #PolKitSession objects. Use the
 * polkit_authorization_constraint_check_caller() and
 * polkit_authorization_constraint_check_session() methods for that
 * instead.
 *
 * Returns: flags from #PolKitAuthorizationConstraintFlags
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraintFlags
polkit_authorization_constraint_get_flags (PolKitAuthorizationConstraint *authc)
{
        kit_return_val_if_fail (authc != NULL, FALSE);
        return authc->flags;
}

/**
 * polkit_authorization_constraint_get_null:
 *
 * Get a #PolKitAuthorizationConstraint object that represents no constraints.
 *
 * Returns: the constraint; the caller shall not unref this object
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_null (void)
{
        return &_null_constraint;
}

/**
 * polkit_authorization_constraint_get_require_local:
 *
 * Get a #PolKitAuthorizationConstraint object that represents the
 * constraint that the session or caller must be local.
 *
 * Returns: the constraint; the caller shall not unref this object
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_require_local (void)
{
        return &_local_constraint;
}

/**
 * polkit_authorization_constraint_get_require_active:
 *
 * Get a #PolKitAuthorizationConstraint object that represents the
 * constraint that the session or caller must be active.
 *
 * Returns: the constraint; the caller shall not unref this object
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_require_active (void)
{
        return &_active_constraint;
}

/**
 * polkit_authorization_constraint_get_require_local_active:
 *
 * Get a #PolKitAuthorizationConstraint object that represents the
 * constraint that the session or caller must be local and in an
 * active session.
 *
 * Returns: the constraint; the caller shall not unref this object
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_require_local_active (void)
{
        return &_local_active_constraint;
}

/**
 * polkit_authorization_constraint_to_string:
 * @authc: the object
 * @out_buf: buffer to store the string representation in
 * @buf_size: size of buffer
 *
 * Get a textual representation of the constraint; this is only useful
 * for serializing; it's a machine, not human, readable string.
 *
 * Returns: Number of characters written (not including trailing
 * '\0'). If the output was truncated due to the buffer being too
 * small, buf_size will be returned. Thus, a return value of buf_size
 * or more indicates that the output was truncated (see snprintf(3))
 * or an error occured.
 *
 * Since: 0.7
 */
size_t
polkit_authorization_constraint_to_string (PolKitAuthorizationConstraint *authc, char *out_buf, size_t buf_size)
{
        kit_return_val_if_fail (authc != NULL, buf_size);

        switch (authc->flags) {
        default:
        case 0:
                return snprintf (out_buf, buf_size, "none");

        case POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL:
                return snprintf (out_buf, buf_size, "local");

        case POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE:
                return snprintf (out_buf, buf_size, "active");

        case POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL|POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE:
                return snprintf (out_buf, buf_size, "local+active");
        }
}

/**
 * polkit_authorization_constraint_from_string:
 * @str: textual representation of constraint
 *
 * Construct a constraint from a textual representation as returned by
 * polkit_authorization_constraint_to_string().
 *
 * Returns: the constraint or #NULL if the string coulnd't be parsed.
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_from_string (const char *str)
{
        PolKitAuthorizationConstraint *ret;

        kit_return_val_if_fail (str != NULL, NULL);

        ret = NULL;

        if (strcmp (str, "none") == 0) {
                ret = polkit_authorization_constraint_get_null ();
                goto out;
        } else if (strcmp (str, "local") == 0) {
                ret = polkit_authorization_constraint_get_require_local ();
                goto out;
        } else if (strcmp (str, "active") == 0) {
                ret = polkit_authorization_constraint_get_require_active ();
                goto out;
        } else if (strcmp (str, "local+active") == 0) {
                ret = polkit_authorization_constraint_get_require_local_active ();
                goto out;
        }

out:
        return ret;
}

/**
 * polkit_authorization_constraint_get_from_caller:
 * @caller: caller
 *
 * Given a caller, return the most restrictive constraint
 * possible. For example, if the caller is local and active, a
 * constraint requiring this will be returned. 
 *
 * This function is typically used when the caller obtains an
 * authorization through authentication; the goal is to put a
 * constraints on the authorization such that it's only valid when the
 * caller is in the context as where she obtained it.
 *
 * Returns: a #PolKitConstraint object; this function will never return #NULL.
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_from_caller (PolKitCaller *caller)
{
        polkit_bool_t is_local;
        polkit_bool_t is_active;
        PolKitSession *session;
        PolKitAuthorizationConstraint *ret;

        /* caller is not in a session so use the null constraint */
        if (!polkit_caller_get_ck_session (caller, &session) || session == NULL) {
                ret = polkit_authorization_constraint_get_null ();
                goto out;
        }

        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (is_local) {
                if (is_active) {
                        ret = polkit_authorization_constraint_get_require_local_active ();
                } else {
                        ret = polkit_authorization_constraint_get_require_local ();
                }
        } else {
                if (is_active) {
                        ret = polkit_authorization_constraint_get_require_active ();
                } else {
                        ret = polkit_authorization_constraint_get_null ();
                }
        }

out:
        return ret;
}


/**
 * polkit_authorization_constraint_equal:
 * @a: first constraint
 * @b: first constraint
 *
 * Determines if two constraints are equal
 *
 * Returns: #TRUE only if the given constraints are equal
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_authorization_constraint_equal (PolKitAuthorizationConstraint *a, PolKitAuthorizationConstraint *b)
{
        kit_return_val_if_fail (a != NULL, FALSE);
        kit_return_val_if_fail (b != NULL, FALSE);

        return a->flags == b->flags;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_tst1 (PolKitSession *s, PolKitAuthorizationConstraint *ac, polkit_bool_t *out_result)
{
        polkit_bool_t oom;
        PolKitCaller *c;

        oom = TRUE;

        if (s == NULL)
                goto out;

        *out_result = polkit_authorization_constraint_check_session (ac, s);

        if ((c = polkit_caller_new ()) != NULL) {
                if (ac->flags == 0)  {
                        kit_assert (polkit_authorization_constraint_check_caller (ac, c) == TRUE);
                } else {
                        kit_assert (polkit_authorization_constraint_check_caller (ac, c) == FALSE);
                }

                kit_assert (polkit_caller_set_ck_session (c, s));
                kit_assert (*out_result == polkit_authorization_constraint_check_caller (ac, c));
                polkit_caller_unref (c);
        }

        oom = FALSE;

out:
        return oom;
}

static void
_tst2 (PolKitAuthorizationConstraint *ac)
{
        char buf[256];
        PolKitAuthorizationConstraint *ac2;

        /* not enough space */
        kit_assert (polkit_authorization_constraint_to_string (ac, buf, 2) >= 2);

        kit_assert (polkit_authorization_constraint_to_string (ac, buf, sizeof (buf)) < sizeof (buf));
        if ((ac2 = polkit_authorization_constraint_from_string (buf)) != NULL) {
                kit_assert (polkit_authorization_constraint_equal (ac, ac2) == TRUE);
                polkit_authorization_constraint_unref (ac2);
        }
}

static polkit_bool_t
_tst3 (PolKitSession *s, PolKitAuthorizationConstraint *compare_to, polkit_bool_t *ret)
{
        PolKitAuthorizationConstraint *ac;
        polkit_bool_t is_oom;
        PolKitCaller *c;

        is_oom = TRUE;

        if (s == NULL)
                goto out;

        if ((c = polkit_caller_new ()) != NULL) {
                ac = polkit_authorization_constraint_get_from_caller (c);
                kit_assert (polkit_authorization_constraint_equal (ac, polkit_authorization_constraint_get_null ()));


                kit_assert (polkit_caller_set_ck_session (c, s));

                ac = polkit_authorization_constraint_get_from_caller (c);

                *ret = polkit_authorization_constraint_equal (ac, compare_to);

                polkit_caller_unref (c);
                polkit_authorization_constraint_unref (ac);

                is_oom = FALSE;
        }


out:
        return is_oom;
}

static polkit_bool_t
_run_test (void)
{
        PolKitAuthorizationConstraint *ac;
        PolKitAuthorizationConstraintFlags flags;
        PolKitSession *s_active;
        PolKitSession *s_inactive;
        PolKitSession *s_active_remote;
        PolKitSession *s_inactive_remote;
        polkit_bool_t ret;
        int n;

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

        /* null constraint */
        kit_assert ((ac = polkit_authorization_constraint_get_null ()) != NULL);
        polkit_authorization_constraint_ref (ac);
        polkit_authorization_constraint_unref (ac);
        flags = polkit_authorization_constraint_get_flags (ac);
        kit_assert (flags == 0);
        kit_assert (_tst1 (s_active, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_active_remote, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive_remote, ac, &ret) || ret == TRUE);
        _tst2 (ac);

        /* local constraint */
        kit_assert ((ac = polkit_authorization_constraint_get_require_local ()) != NULL);
        flags = polkit_authorization_constraint_get_flags (ac);
        kit_assert (flags == POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL);
        kit_assert (_tst1 (s_active, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_active_remote, ac, &ret) || ret == FALSE);
        kit_assert (_tst1 (s_inactive_remote, ac, &ret) || ret == FALSE);
        _tst2 (ac);

        /* active constraint */
        kit_assert ((ac = polkit_authorization_constraint_get_require_active ()) != NULL);
        flags = polkit_authorization_constraint_get_flags (ac);
        kit_assert (flags == POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE);
        kit_assert (_tst1 (s_active, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive, ac, &ret) || ret == FALSE);
        kit_assert (_tst1 (s_active_remote, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive_remote, ac, &ret) || ret == FALSE);
        _tst2 (ac);

        /* local+active constraint */
        kit_assert ((ac = polkit_authorization_constraint_get_require_local_active ()) != NULL);
        flags = polkit_authorization_constraint_get_flags (ac);
        kit_assert (flags == (POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_LOCAL|
                            POLKIT_AUTHORIZATION_CONSTRAINT_REQUIRE_ACTIVE));
        kit_assert (_tst1 (s_active, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive, ac, &ret) || ret == FALSE);
        kit_assert (_tst1 (s_active_remote, ac, &ret) || ret == FALSE);
        kit_assert (_tst1 (s_inactive_remote, ac, &ret) || ret == FALSE);
        _tst2 (ac);

        for (n = 0; n < 4; n++) {
                PolKitSession *s;
                polkit_bool_t expected[4];

                switch (n) {
                case 0:
                        s = s_active;
                        expected[0] = TRUE;
                        expected[1] = FALSE;
                        expected[2] = FALSE;
                        expected[3] = FALSE;
                        break;
                case 1:
                        s = s_inactive;
                        expected[0] = FALSE;
                        expected[1] = TRUE;
                        expected[2] = FALSE;
                        expected[3] = FALSE;
                        break;
                case 2:
                        s = s_active_remote;
                        expected[0] = FALSE;
                        expected[1] = FALSE;
                        expected[2] = TRUE;
                        expected[3] = FALSE;
                        break;
                case 3:
                        s = s_inactive_remote;
                        expected[0] = FALSE;
                        expected[1] = FALSE;
                        expected[2] = FALSE;
                        expected[3] = TRUE;
                        break;
                }

                kit_assert (_tst3 (s, polkit_authorization_constraint_get_require_local_active (), &ret) || ret == expected[0]);
                kit_assert (_tst3 (s, polkit_authorization_constraint_get_require_local (), &ret) || ret == expected[1]);
                kit_assert (_tst3 (s, polkit_authorization_constraint_get_require_active (), &ret) || ret == expected[2]);
                kit_assert (_tst3 (s, polkit_authorization_constraint_get_null (), &ret) || ret == expected[3]);
        }

        if ((ac = _polkit_authorization_constraint_new ("local+active")) != NULL) {
                polkit_authorization_constraint_validate (ac);
                polkit_authorization_constraint_debug (ac);
                polkit_authorization_constraint_ref (ac);
                polkit_authorization_constraint_unref (ac);
                polkit_authorization_constraint_unref (ac);
        }
        
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


KitTest _test_authorization_constraint = {
        "polkit_authorization_constraint",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

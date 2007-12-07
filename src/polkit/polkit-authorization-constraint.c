/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization-constraint.c : Conditions that must be
 * satisfied in order for an authorization to apply
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
#include <limits.h>

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
        PolKitAuthorizationConstraintType type;

        union {
                struct {
                        char *path;
                } exe;
                struct {
                        char *context;
                } selinux_context;
        };
};

static PolKitAuthorizationConstraint _local_constraint = {-1, 
                                                          POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL};

static PolKitAuthorizationConstraint _active_constraint = {-1, 
                                                          POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE};

static PolKitAuthorizationConstraint *
_polkit_authorization_constraint_new (void)
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

        switch (authc->type) {
        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL:
        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE:
                break;

        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE:
                kit_free (authc->exe.path);
                break;

        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT:
                kit_free (authc->selinux_context.context);
                break;
        }

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
        _pk_debug ("PolKitAuthorizationConstraint: refcount=%d type=%d", authc->refcount, authc->type);
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
 * the given constraint.
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

        if (authc->type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL)  {
                if (!is_local)
                        goto out;
        }

        if (authc->type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE)  {
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
        int n;
        pid_t pid;
        char *selinux_context;
        char buf[PATH_MAX];
        polkit_bool_t ret;
        PolKitSession *session;

        kit_return_val_if_fail (authc != NULL, FALSE);
        kit_return_val_if_fail (caller != NULL, FALSE);

        ret = FALSE;

        /* caller may not be in a session */

        switch (authc->type) {
        /* explicit fallthrough */
        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL:
        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE:
                if (polkit_caller_get_ck_session (caller, &session) && session != NULL) {
                        ret = polkit_authorization_constraint_check_session (authc, session);
                }
                break;

        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE:
                if (polkit_caller_get_pid (caller, &pid)) {

                        /* we may be running unprivileged.. so optionally use the helper. Requires the calling
                         * process (this one) to have the org.freedesktop.policykit.read authorization.
                         *
                         * An example of this is HAL (running as user 'haldaemon').
                         */
                        n = polkit_sysdeps_get_exe_for_pid_with_helper (pid, buf, sizeof (buf));

                        if (n != -1 && n < (int) sizeof (buf)) {
                                if (strcmp (authc->exe.path, buf) == 0) {
                                        ret = TRUE;
                                }
                        }
                }

                break;

        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT:
                if (polkit_caller_get_selinux_context (caller, &selinux_context) && selinux_context != NULL) {
                        if (strcmp (authc->selinux_context.context, selinux_context) == 0) {
                                ret = TRUE;
                        }
                } else {
                        /* if SELinux context is not set then SELinux is not enabled (or the
                         * caller made a mistake and didn't set it); thus, the authorization can
                         * never apply 
                         */
                        ret = TRUE;
                }
                break;
        }

        return ret;
}

/**
 * polkit_authorization_constraint_type:
 * @authc: the object
 *
 * Describe the constraint; this is only useful when inspecting an
 * authorization to present information to the user (e.g. as
 * polkit-auth(1) does).
 *
 * Returns: type from #PolKitAuthorizationConstraintType
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraintType
polkit_authorization_constraint_type (PolKitAuthorizationConstraint *authc)
{
        kit_return_val_if_fail (authc != NULL, FALSE);
        return authc->type;
}

/**
 * polkit_authorization_constraint_get_exe:
 * @authc: the object
 *
 * Get the exe path for the constraint.
 *
 * Returns: The exe path or #NULL if type isn't
 * #POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE. Caller shall not
 * free this string.
 * 
 * Since: 0.8
 */
const char *
polkit_authorization_constraint_get_exe (PolKitAuthorizationConstraint *authc)
{
        kit_return_val_if_fail (authc != NULL, NULL);
        kit_return_val_if_fail (authc->type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE, NULL);

        return authc->exe.path;
}

/**
 * polkit_authorization_constraint_get_selinux_context:
 * @authc: the object
 *
 * Get the SELinux context for the constraint.
 *
 * Returns: The selinux context or #NULL if type isn't
 * #POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT. Caller
 * shall not free this string.
 * 
 * Since: 0.8
 */
const char *
polkit_authorization_constraint_get_selinux_context (PolKitAuthorizationConstraint *authc)
{
        kit_return_val_if_fail (authc != NULL, NULL);
        kit_return_val_if_fail (authc->type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT, NULL);

        return authc->selinux_context.context;
}

/**
 * polkit_authorization_constraint_get_require_local:
 *
 * Get a #PolKitAuthorizationConstraint object that represents the
 * constraint that the session or caller must be local.
 *
 * Returns: the constraint
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
 * Returns: the constraint
 *
 * Since: 0.7
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_require_active (void)
{
        return &_active_constraint;
}

/**
 * polkit_authorization_constraint_get_require_exe:
 * @path: path to program
 *
 * Get a #PolKitAuthorizationConstraint object that represents the
 * constraint that the caller must be a specific program
 *
 * Returns: the constraint or #NULL on OOM
 *
 * Since: 0.8
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_require_exe (const char *path)
{
        PolKitAuthorizationConstraint *authc;

        kit_return_val_if_fail (path != NULL, NULL);

        authc = _polkit_authorization_constraint_new ();
        if (authc == NULL)
                goto out;
        authc->type = POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE;
        authc->exe.path = kit_strdup (path);
        if (authc->exe.path == NULL) {
                polkit_authorization_constraint_unref (authc);
                authc = NULL;
        }

out:
        return authc;
}

/**
 * polkit_authorization_constraint_get_require_selinux_context:
 * @context: SELinux context
 *
 * Get a #PolKitAuthorizationConstraint object that represents the
 * constraint that the caller must be in a specific SELinux context.
 *
 * Returns: the constraint or #NULL on OOM
 *
 * Since: 0.8
 */
PolKitAuthorizationConstraint *
polkit_authorization_constraint_get_require_selinux_context (const char *context)
{
        PolKitAuthorizationConstraint *authc;

        kit_return_val_if_fail (context != NULL, NULL);

        authc = _polkit_authorization_constraint_new ();
        if (authc == NULL)
                goto out;
        authc->type = POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT;
        authc->selinux_context.context = kit_strdup (context);
        if (authc->selinux_context.context == NULL) {
                polkit_authorization_constraint_unref (authc);
                authc = NULL;
        }

out:
        return authc;
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

        switch (authc->type) {
        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL:
                return snprintf (out_buf, buf_size, "local");

        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE:
                return snprintf (out_buf, buf_size, "active");

        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE:
                return snprintf (out_buf, buf_size, "exe:%s", authc->exe.path);
                
        case POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT:
                return snprintf (out_buf, buf_size, "selinux_context:%s", authc->selinux_context.context);
        }

        return 0;
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

        if (strcmp (str, "local") == 0) {
                ret = polkit_authorization_constraint_get_require_local ();
                goto out;
        } else if (strcmp (str, "active") == 0) {
                ret = polkit_authorization_constraint_get_require_active ();
                goto out;
        } else if (strncmp (str, "exe:", 4) == 0 && strlen (str) > 4) {
                ret = polkit_authorization_constraint_get_require_exe (str + 4);
                goto out;
        } else if (strncmp (str, "selinux_context:", 16) == 0 && strlen (str) > 16) {
                ret = polkit_authorization_constraint_get_require_selinux_context (str + 16);
                goto out;
        }

out:
        return ret;
}

/**
 * polkit_authorization_constraint_get_from_caller:
 * @caller: caller
 * @out_array: return location for constraints
 * @array_size: size of the passed array
 *
 * Given a caller, return the set of most restrictive constraints
 * possible. For example, if the caller is local and active, a set
 * constraints requiring this will be returned.
 *
 * This function is typically used when the caller obtains an
 * authorization through authentication; the goal is to put
 * constraints on the authorization such that it's only valid when the
 * caller is in the context as where she obtained it.
 *
 * The caller must unref all the created objects using
 * polkit_authorization_constraint_unref().
 *
 * Returns: If OOM -1 is returned. This function do not create more
 * than @array_size constraints (including the trailing %NULL). If the
 * output was truncated due to this limit then the return value is the
 * number of objects (not including the trailing %NULL) which would
 * have been written to the final array if enough space had been
 * available. Thus, a return value of @array_size or more means that
 * the output was truncated.
 *
 * Since: 0.7
 */
int
polkit_authorization_constraint_get_from_caller (PolKitCaller *caller, 
                                                 PolKitAuthorizationConstraint **out_array, 
                                                 size_t array_size)
{
        pid_t pid;
        char *selinux_context;
        int ret;
        polkit_bool_t is_local;
        polkit_bool_t is_active;
        PolKitSession *session;
        char path[PATH_MAX];
        int n;

        kit_return_val_if_fail (caller != NULL, 0);
        kit_return_val_if_fail (out_array != NULL, 0);

        ret = 0;

        if (!polkit_caller_get_ck_session (caller, &session) || session == NULL) {
                goto out;
        }
        
        polkit_session_get_ck_is_local (session, &is_local);
        polkit_session_get_ck_is_active (session, &is_active);

        if (is_local) {
                if (ret < (int) array_size)
                        out_array[ret] = polkit_authorization_constraint_get_require_local ();
                ret++;
        } 

        if (is_active) {
                if (ret < (int) array_size)
                        out_array[ret] = polkit_authorization_constraint_get_require_active ();
                ret++;
        }

        /* constrain to callers program */
        if (polkit_caller_get_pid (caller, &pid)) {
                /* So the program to receive a constraint may besetuid root... so we may need some
                 * help to get the exepath.. Therefore use _with_helper().
                 *
                 * This works because this function is normally only called from polkit-grant-helper which
                 * is setgid polkituser.. this means that _with_helper will succeed.
                 *
                 * An example of this is pulseaudio...
                 */
                n = polkit_sysdeps_get_exe_for_pid_with_helper (pid, path, sizeof (path));
                if (n != -1 && n < (int) sizeof (path)) {
                        PolKitAuthorizationConstraint *c;

                        c = polkit_authorization_constraint_get_require_exe (path);
                        if (c == NULL)
                                goto oom;

                        if (ret < (int) array_size)
                                out_array[ret] = c;

                        ret++;
                }
        }

        /* constrain to callers SELinux context */
        if (polkit_caller_get_selinux_context (caller, &selinux_context) && selinux_context != NULL) {
                PolKitAuthorizationConstraint *c;

                c = polkit_authorization_constraint_get_require_selinux_context (selinux_context);
                if (c == NULL)
                        goto oom;

                if (ret < (int) array_size)
                        out_array[ret] = c;
                
                ret++;
        }

out:
        if (ret < (int) array_size)
                out_array[ret] = NULL;

        return ret;

oom:
        for (n = 0; n < ret; n++) {
                polkit_authorization_constraint_unref (out_array[n]);
        }
        return -1;
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
        polkit_bool_t ret;

        kit_return_val_if_fail (a != NULL, FALSE);
        kit_return_val_if_fail (b != NULL, FALSE);

        ret = FALSE;

        if (a->type != b->type)
                goto out;

        if (a->type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_EXE) {
                if (strcmp (a->exe.path, b->exe.path) != 0)
                        goto out;
        } else if (a->type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_SELINUX_CONTEXT) {
                if (strcmp (a->selinux_context.context, b->selinux_context.context) != 0)
                        goto out;
        }

        ret = TRUE;

out:
        return ret;
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
                /* we know that the ac's passed always will be REQUIRE_ACTIVE or REQUIRE_LOCAL */
                kit_assert (polkit_authorization_constraint_check_caller (ac, c) == FALSE);

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

#if 0
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
#endif

static polkit_bool_t
_run_test (void)
{
        PolKitAuthorizationConstraint *ac;
        PolKitAuthorizationConstraint *ac2;
        PolKitAuthorizationConstraintType type;
        PolKitSession *s_active;
        PolKitSession *s_inactive;
        PolKitSession *s_active_remote;
        PolKitSession *s_inactive_remote;
        polkit_bool_t ret;
        char buf[256];

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

        /* local constraint */
        kit_assert ((ac = polkit_authorization_constraint_get_require_local ()) != NULL);
        type = polkit_authorization_constraint_type (ac);
        kit_assert (type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_LOCAL);
        kit_assert (_tst1 (s_active, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_active_remote, ac, &ret) || ret == FALSE);
        kit_assert (_tst1 (s_inactive_remote, ac, &ret) || ret == FALSE);
        _tst2 (ac);

        /* active constraint */
        kit_assert ((ac = polkit_authorization_constraint_get_require_active ()) != NULL);
        type = polkit_authorization_constraint_type (ac);
        kit_assert (type == POLKIT_AUTHORIZATION_CONSTRAINT_TYPE_REQUIRE_ACTIVE);
        kit_assert (_tst1 (s_active, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive, ac, &ret) || ret == FALSE);
        kit_assert (_tst1 (s_active_remote, ac, &ret) || ret == TRUE);
        kit_assert (_tst1 (s_inactive_remote, ac, &ret) || ret == FALSE);
        _tst2 (ac);


#if 0
        /* TODO: redo these tests; they are supposed to to verify that 
         *       polkit_authorization_constraint_get_from_caller() works()
         */
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
#endif

        if ((ac = _polkit_authorization_constraint_new ()) != NULL) {
                polkit_authorization_constraint_validate (ac);
                polkit_authorization_constraint_debug (ac);
                polkit_authorization_constraint_ref (ac);
                polkit_authorization_constraint_unref (ac);
                polkit_authorization_constraint_unref (ac);
        }

        char our_exe[256];
        int n;
        n = polkit_sysdeps_get_exe_for_pid (getpid (), our_exe, sizeof (our_exe));
        kit_assert (n != -1);
        kit_assert (n < (int) sizeof (our_exe));

        if ((ac = polkit_authorization_constraint_get_require_exe (our_exe)) != NULL) {
                const char *s;
                PolKitCaller *c;

                kit_assert ((s = polkit_authorization_constraint_get_exe (ac)) != NULL && strcmp (s, our_exe) == 0);
                kit_assert (polkit_authorization_constraint_to_string (ac, buf, sizeof (buf)) < sizeof (buf));
                if ((ac2 = polkit_authorization_constraint_from_string (buf)) != NULL) {
                        kit_assert (polkit_authorization_constraint_equal (ac, ac2));
                        polkit_authorization_constraint_unref (ac2);
                }

                if ((c = polkit_caller_new ()) != NULL) {
                        kit_assert (polkit_caller_set_pid (c, getpid ()));
                        kit_assert (polkit_authorization_constraint_check_caller (ac, c));
                        kit_assert (polkit_caller_set_pid (c, getppid ()));
                        kit_assert (! polkit_authorization_constraint_check_caller (ac, c));
                        polkit_caller_unref (c);
                }
                

                polkit_authorization_constraint_unref (ac);
        }

        if ((ac = polkit_authorization_constraint_get_require_selinux_context ("httpd_exec_t")) != NULL) {
                const char *s;
                PolKitCaller *c;

                kit_assert ((s = polkit_authorization_constraint_get_selinux_context (ac)) != NULL && 
                            strcmp (s, "httpd_exec_t") == 0);
                kit_assert (polkit_authorization_constraint_to_string (ac, buf, sizeof (buf)) < sizeof (buf));
                if ((ac2 = polkit_authorization_constraint_from_string (buf)) != NULL) {
                        kit_assert (polkit_authorization_constraint_equal (ac, ac2));
                        polkit_authorization_constraint_unref (ac2);
                }

                if ((c = polkit_caller_new ()) != NULL) {
                        kit_assert (polkit_caller_set_pid (c, getpid ()));

                        if (polkit_caller_set_selinux_context (c, "httpd_exec_t")) {
                                kit_assert (polkit_authorization_constraint_check_caller (ac, c));
                        } else {
                                kit_assert (errno == ENOMEM);
                        }

                        if (polkit_caller_set_selinux_context (c, "hald_exec_t")) {
                                kit_assert (! polkit_authorization_constraint_check_caller (ac, c));
                        } else {
                                kit_assert (errno == ENOMEM);
                        }

                        polkit_caller_unref (c);
                }

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

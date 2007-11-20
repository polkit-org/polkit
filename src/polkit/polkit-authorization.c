/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization.c : Represents an entry in the authorization
 * database
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
#include "polkit-authorization.h"
#include "polkit-utils.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-authorization
 * @title: Authorization Entry
 * @short_description: An entry in the autothorization database
 *
 * This class is used to represent entries in the authorization
 * database.
 *
 * Since: 0.7
 **/

/**
 * PolKitAuthorization:
 *
 * Objects of this class are used to represent entries in the
 * authorization database.
 *
 * Since: 0.7
 **/
struct _PolKitAuthorization
{
        int refcount;

        char *entry_in_auth_file;

        PolKitAuthorizationScope scope;
        PolKitAuthorizationConstraint *constraint;

        char *action_id;
        uid_t uid;
        time_t when;
        uid_t authenticated_as_uid;

        pid_t pid;
        polkit_uint64_t pid_start_time;

        polkit_bool_t explicitly_granted;
        uid_t explicitly_granted_by;

        polkit_bool_t is_negative;

        char *session_id;
};

const char *
_polkit_authorization_get_authfile_entry (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, NULL);
        return auth->entry_in_auth_file;
}

#ifdef POLKIT_AUTHDB_DEFAULT

PolKitAuthorization *
_polkit_authorization_new_for_uid (const char *entry_in_auth_file, uid_t uid)
{
        char **t;
        size_t num_t;
        char *ep;
        PolKitAuthorization *auth;
        int n;

        kit_return_val_if_fail (entry_in_auth_file != NULL, NULL);

        t = NULL;

        auth = kit_new0 (PolKitAuthorization, 1);
        if (auth == NULL)
                goto oom;

        auth->refcount = 1;
        auth->entry_in_auth_file = kit_strdup (entry_in_auth_file);
        if (auth->entry_in_auth_file == NULL)
                goto oom;

        auth->uid = uid;

        t = kit_strsplit (entry_in_auth_file, ':', &num_t);
        if (t == NULL)
                goto oom;

/*
 * pid:
 *       grant_line = g_strdup_printf ("process:%d:%Lu:%s:%Lu:%d:%s\n", 
 *                                     caller_pid, 
 *                                     pid_start_time, 
 *                                     action_id,
 *                                     (polkit_uint64_t) now.tv_sec,
 *                                     user_authenticated_as,
 *                                     cbuf);
 */
        n = 1;

        if (strcmp (t[0], "process") == 0 ||
            strcmp (t[0], "process-one-shot") == 0) {
                if (num_t != 7)
                        goto error;

                if (strcmp (t[0], "process") == 0)
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_PROCESS;
                else
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT;

                auth->pid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->pid_start_time = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = kit_strdup (t[n++]);
                if (auth->action_id == NULL)
                        goto oom;

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->authenticated_as_uid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;
        }
/*
 *        grant_line = g_strdup_printf ("session:%s:%s:%Lu:%s:%d:%s\n", 
 *                                      session_objpath,
 *                                      action_id,
 *                                      (polkit_uint64_t) now.tv_sec,
 *                                      user_authenticated_as,
 *                                      cbuf);
 */
        else if (strcmp (t[0], "session") == 0) {
                if (num_t != 6)
                        goto error;

                auth->scope = POLKIT_AUTHORIZATION_SCOPE_SESSION;

                auth->session_id = kit_strdup (t[n++]);
                if (auth->session_id == NULL)
                        goto oom;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = kit_strdup (t[n++]);
                if (auth->action_id == NULL)
                        goto oom;

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->authenticated_as_uid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;
        }

/*
 * always:
 *        grant_line = g_strdup_printf ("always:%s:%Lu:%s:%d:%s\n", 
 *                                      action_id,
 *                                      (polkit_uint64_t) now.tv_sec,
 *                                      user_authenticated_as,
 *                                      cbuf);
 *
 */
        else if (strcmp (t[0], "always") == 0) {
                if (num_t != 5)
                        goto error;

                auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = kit_strdup (t[n++]);
                if (auth->action_id == NULL)
                        goto oom;

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->authenticated_as_uid = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;
        }
/*
 * grant:
 *                     "grant:%d:%s:%Lu:%d:%s\n",
 *                     action_id,
 *                     (polkit_uint64_t) now.tv_sec,
 *                     invoking_uid,
 *                     authc_str) >= (int) sizeof (grant_line)) {
 *
 */
        else if (strcmp (t[0], "grant") == 0 ||
                 strcmp (t[0], "grant-negative") == 0) {

                if (num_t != 5)
                        goto error;

                if (strcmp (t[0], "grant-negative") == 0) {
                        auth->is_negative = TRUE;
                }

                auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;
                auth->explicitly_granted = TRUE;

                if (!polkit_action_validate_id (t[n]))
                        goto error;
                auth->action_id = kit_strdup (t[n++]);
                if (auth->action_id == NULL)
                        goto oom;

                auth->when = strtoull (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->explicitly_granted_by = strtoul (t[n++], &ep, 10);
                if (*ep != '\0')
                        goto error;

                auth->constraint = polkit_authorization_constraint_from_string (t[n++]);
                if (auth->constraint == NULL)
                        goto error;

        } else {
                goto error;
        }

        kit_strfreev (t);
        return auth;

error:
        //g_warning ("Error parsing token %d from line '%s'", n, entry_in_auth_file);
oom:
        if (auth != NULL)
                polkit_authorization_unref (auth);
        if (t != NULL)
                kit_strfreev (t);
        return NULL;
}

#endif /* POLKIT_AUTHDB_DEFAULT */

/**
 * polkit_authorization_ref:
 * @auth: the authorization object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 *
 * Since: 0.7
 **/
PolKitAuthorization *
polkit_authorization_ref (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, auth);
        auth->refcount++;
        return auth;
}

/**
 * polkit_authorization_unref:
 * @auth: the authorization object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 *
 * Since: 0.7
 **/
void
polkit_authorization_unref (PolKitAuthorization *auth)
{
        kit_return_if_fail (auth != NULL);
        auth->refcount--;
        if (auth->refcount > 0) 
                return;

        kit_free (auth->entry_in_auth_file);
        kit_free (auth->action_id);
        kit_free (auth->session_id);
        if (auth->constraint != NULL)
                polkit_authorization_constraint_unref (auth->constraint);
        kit_free (auth);
}

/**
 * polkit_authorization_debug:
 * @auth: the object
 * 
 * Print debug details
 *
 * Since: 0.7
 **/
void
polkit_authorization_debug (PolKitAuthorization *auth)
{
        kit_return_if_fail (auth != NULL);
        _pk_debug ("PolKitAuthorization: refcount=%d", auth->refcount);
        _pk_debug (" scope          = %d",  auth->scope);
        _pk_debug (" pid            = %d",  auth->pid);
        _pk_debug (" pid_start_time = %Lu", auth->pid_start_time);
        _pk_debug (" action_id      = %s",  auth->action_id);
        _pk_debug (" when           = %Lu", (polkit_uint64_t) auth->when);
        _pk_debug (" auth_as_uid    = %d",  auth->authenticated_as_uid);
}

/**
 * polkit_authorization_validate:
 * @auth: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 *
 * Since: 0.7
 **/
polkit_bool_t
polkit_authorization_validate (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, FALSE);

        return TRUE;
}

/**
 * polkit_authorization_get_action_id:
 * @auth: the object
 *
 * Get the action this authorization is for
 *
 * Returns: the action id. Caller should not free this string.
 *
 * Since: 0.7
 */ 
const char *
polkit_authorization_get_action_id (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, NULL);

        return auth->action_id;
}

/**
 * polkit_authorization_get_scope:
 * @auth: the object
 *
 * Get the scope of the authorization; e.g. whether it's confined to a
 * single process, a single session or can be retained
 * indefinitely. Also keep in mind that an authorization is subject to
 * constraints, see polkit_authorization_get_constraint() for details.
 *
 * Returns: the scope
 *
 * Since: 0.7
 */ 
PolKitAuthorizationScope
polkit_authorization_get_scope (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, 0);

        return auth->scope;
}

/**
 * polkit_authorization_scope_process_get_pid:
 * @auth: the object
 * @out_pid: return location
 * @out_pid_start_time: return location
 *
 * If scope is #POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT or
 * #POLKIT_AUTHORIZATION_SCOPE_PROCESS, get information about what
 * process the authorization is confined to. 
 *
 * As process identifiers can be recycled, the start time of the
 * process (the unit is not well-defined; on Linux it's the number of
 * milliseconds since the system was started) is also returned.
 *
 * Returns: #TRUE if information was returned
 *
 * Since: 0.7
 */ 
polkit_bool_t
polkit_authorization_scope_process_get_pid (PolKitAuthorization *auth, 
                                            pid_t *out_pid, 
                                            polkit_uint64_t *out_pid_start_time)
{
        kit_return_val_if_fail (auth != NULL, FALSE);
        kit_return_val_if_fail (out_pid != NULL, FALSE);
        kit_return_val_if_fail (out_pid_start_time != NULL, FALSE);
        kit_return_val_if_fail (auth->scope == POLKIT_AUTHORIZATION_SCOPE_PROCESS || 
                              auth->scope == POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT, FALSE);

        *out_pid = auth->pid;
        *out_pid_start_time = auth->pid_start_time;

        return TRUE;
}

/**
 * polkit_authorization_scope_session_get_ck_objref:
 * @auth: the object
 *
 * Gets the ConsoleKit object path for the session the authorization
 * is confined to.
 *
 * Returns: #NULL if scope wasn't session
 *
 * Since: 0.7
 */ 
const char *
polkit_authorization_scope_session_get_ck_objref (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, FALSE);
        kit_return_val_if_fail (auth->scope == POLKIT_AUTHORIZATION_SCOPE_SESSION, FALSE);

        return auth->session_id;
}

/**
 * polkit_authorization_get_uid:
 * @auth: the object
 *
 * Gets the UNIX user id for the user the authorization is confined
 * to.
 *
 * Returns: The UNIX user id for whom the authorization is confied to
 *
 * Since: 0.7
 */ 
uid_t
polkit_authorization_get_uid (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, 0);
        return auth->uid;
}

/**
 * polkit_authorization_get_time_of_grant:
 * @auth: the object
 *
 * Returns the point in time the authorization was granted. The value
 * is UNIX time, e.g. number of seconds since the Epoch Jan 1, 1970
 * 0:00 UTC.
 *
 * Returns: When authorization was granted
 *
 * Since: 0.7
 */ 
time_t
polkit_authorization_get_time_of_grant (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, 0);
        return auth->when;
}

/**
 * polkit_authorization_was_granted_via_defaults:
 * @auth: the object
 * @out_user_authenticated_as: return location
 *
 * Determine if the authorization was obtained by the user by
 * authenticating as himself or an administrator via the the
 * "defaults" section in the <literal>.policy</literal> file for the
 * action (e.g.  "allow_any", "allow_inactive", "allow_active"). 
 *
 * Compare with polkit_authorization_was_granted_explicitly() - only
 * one of these functions can return #TRUE.
 *
 * Returns: #TRUE if the authorization was obtained by the user
 * himself authenticating.
 *
 * Since: 0.7
 */ 
polkit_bool_t 
polkit_authorization_was_granted_via_defaults (PolKitAuthorization *auth,
                                               uid_t *out_user_authenticated_as)
{
        kit_return_val_if_fail (auth != NULL, FALSE);
        kit_return_val_if_fail (out_user_authenticated_as != NULL, FALSE);

        if (auth->explicitly_granted)
                return FALSE;

        *out_user_authenticated_as = auth->authenticated_as_uid;
        return TRUE;
}

/**
 * polkit_authorization_was_granted_explicitly:
 * @auth: the object
 * @out_by_whom: return location
 * @out_is_negative: return location
 *
 * Determine if the authorization was explicitly granted by a
 * sufficiently privileged user.
 *
 * Compare with polkit_authorization_was_granted_via_defaults() - only
 * one of these functions can return #TRUE.
 *
 * Returns: #TRUE if the authorization was explicitly granted by a
 * sufficiently privileger user. If %TRUE, the user who granted the
 * authorization is returned in %out_by_whom. If the authorization is
 * negative, %TRUE is returned in %out_is_negative.
 *
 * Since: 0.7
 */ 
polkit_bool_t 
polkit_authorization_was_granted_explicitly (PolKitAuthorization *auth,
                                             uid_t               *out_by_whom,
                                             polkit_bool_t       *out_is_negative)
{
        kit_return_val_if_fail (auth != NULL, FALSE);
        kit_return_val_if_fail (out_by_whom != NULL, FALSE);
        kit_return_val_if_fail (out_is_negative != NULL, FALSE);

        if (!auth->explicitly_granted)
                return FALSE;

        *out_by_whom = auth->explicitly_granted_by;
        *out_is_negative = auth->is_negative;

        return TRUE;
}

/**
 * polkit_authorization_get_constraint:
 * @auth: the object
 *
 * Get the constraint associated with an authorization.
 *
 * Returns: The constraint. Caller shall not unref this object.
 *
 * Since: 0.7
 */ 
PolKitAuthorizationConstraint *
polkit_authorization_get_constraint (PolKitAuthorization *auth)
{
        kit_return_val_if_fail (auth != NULL, FALSE);
        return auth->constraint;
}

#ifdef POLKIT_BUILD_TESTS

#ifdef POLKIT_AUTHDB_DEFAULT

typedef struct {
        const char *entry;
        PolKitAuthorizationScope scope;
        const char *action_id;
        time_t time_of_grant;
        pid_t pid;
        polkit_uint64_t pid_start_time;
        const char *session;
        PolKitAuthorizationConstraint *constraint;
        polkit_bool_t explicit;
        uid_t from;
} TestAuth;

static polkit_bool_t
_run_test (void)
{
        const char *invalid_auths[] = {
                "INVALID_SCOPE",

                /* wrong number of items */
                "process:",
                "session:",
                "always:",
                "grant:",

                /* malformed components */
                "process:14485xyz:26817340:org.gnome.policykit.examples.frobnicate:1194631763:500:local+active",
                "process:14485:26817340xyz:org.gnome.policykit.examples.frobnicate:1194631763:500:local+active",
                "process:14485:26817340:0xyorg.gnome.policykit.examples.frobnicate:1194631763:500:local+active",
                "process:14485:26817340:org.gnome.policykit.examples.frobnicate:1194631763xyz:500:local+active",
                "process:14485:26817340:org.gnome.policykit.examples.frobnicate:1194631763:500xyz:local+active",
                "process:14485:26817340:org.gnome.policykit.examples.frobnicate:1194631763:500:MALFORMED_CONSTRAINT",

                /* TODO: validate ConsoleKit paths
                   "session:xyz/org/freedesktop/ConsoleKit/Session1:org.gnome.policykit.examples.punch:1194631779:500:local+active",*/
                "session:/org/freedesktop/ConsoleKit/Session1:0xyorg.gnome.policykit.examples.punch:1194631779:500:local+active",
                "session:/org/freedesktop/ConsoleKit/Session1:org.gnome.policykit.examples.punch:1194631779xyz:500:local+active",
                "session:/org/freedesktop/ConsoleKit/Session1:org.gnome.policykit.examples.punch:1194631779:500xyz:local+active",
                "session:/org/freedesktop/ConsoleKit/Session1:org.gnome.policykit.examples.punch:1194631779:500:MALFORMED",

                "always:0xyorg.gnome.clockapplet.mechanism.settimezone:1193598494:500:local+active",
                "always:org.gnome.clockapplet.mechanism.settimezone:xyz1193598494:500:local+active",
                "always:org.gnome.clockapplet.mechanism.settimezone:1193598494:xyz500:local+active",
                "always:org.gnome.clockapplet.mechanism.settimezone:1193598494:500:MALFORMED",

                "grant:0xyorg.freedesktop.policykit.read:1194634242:0:none",
                "grant:org.freedesktop.policykit.read:xyz1194634242:0:none",
                "grant:org.freedesktop.policykit.read:1194634242:xyz0:none",
                "grant:org.freedesktop.policykit.read:1194634242:0:MALFORMED",

        };
        size_t num_invalid_auths = sizeof (invalid_auths) / sizeof (const char *);
        TestAuth valid_auths[] = {
                {
                        "always:org.gnome.clockapplet.mechanism.settimezone:1193598494:500:local+active",
                        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
                        "org.gnome.clockapplet.mechanism.settimezone",
                        1193598494,
                        0, 0, NULL,
                        polkit_authorization_constraint_get_require_local_active (),
                        FALSE, 500
                },

                {
                        "process:14485:26817340:org.gnome.policykit.examples.frobnicate:1194631763:500:local+active",
                        POLKIT_AUTHORIZATION_SCOPE_PROCESS,
                        "org.gnome.policykit.examples.frobnicate",
                        1194631763,
                        14485, 26817340, NULL,
                        polkit_authorization_constraint_get_require_local_active (),
                        FALSE, 500
                },

                {
                        "process:14485:26817340:org.gnome.policykit.examples.tweak:1194631774:0:local+active",
                        POLKIT_AUTHORIZATION_SCOPE_PROCESS,
                        "org.gnome.policykit.examples.tweak",
                        1194631774,
                        14485, 26817340, NULL,
                        polkit_authorization_constraint_get_require_local_active (),
                        FALSE, 0
                },

                {
                        "session:/org/freedesktop/ConsoleKit/Session1:org.gnome.policykit.examples.punch:1194631779:500:local+active",
                        POLKIT_AUTHORIZATION_SCOPE_SESSION,
                        "org.gnome.policykit.examples.punch",
                        1194631779,
                        0, 0, "/org/freedesktop/ConsoleKit/Session1",
                        polkit_authorization_constraint_get_require_local_active (),
                        FALSE, 500
                },

                {
                        "process-one-shot:27860:26974819:org.gnome.policykit.examples.jump:1194633344:500:local+active",
                        POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT,
                        "org.gnome.policykit.examples.jump",
                        1194633344,
                        27860, 26974819, NULL,
                        polkit_authorization_constraint_get_require_local_active (),
                        FALSE, 500
                },

                {
                        "grant:org.freedesktop.policykit.read:1194634242:0:none",
                        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
                        "org.freedesktop.policykit.read",
                        1194634242,
                        0, 0, NULL,
                        polkit_authorization_constraint_get_null (),
                        TRUE, 0
                },

        };
        size_t num_valid_auths = sizeof (valid_auths) / sizeof (TestAuth);
        unsigned int n;
        pid_t pid;
        polkit_uint64_t pid_start_time;
        const char *s;
        PolKitAuthorizationConstraint *ac;
        uid_t uid;

        for (n = 0; n < num_valid_auths; n++) {
                PolKitAuthorization *a;
                TestAuth *t = &(valid_auths[n]);

                if ((a = _polkit_authorization_new_for_uid (t->entry, 500)) != NULL) {

                        polkit_authorization_debug (a);
                        polkit_authorization_validate (a);

                        kit_assert (t->scope == polkit_authorization_get_scope (a));
                        kit_assert (t->time_of_grant == polkit_authorization_get_time_of_grant (a));
                        kit_assert (500 == polkit_authorization_get_uid (a));

                        switch (t->scope) {
                        case POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT: /* explicit fallthrough */
                        case POLKIT_AUTHORIZATION_SCOPE_PROCESS:
                                kit_assert (polkit_authorization_scope_process_get_pid (a, &pid, &pid_start_time) && 
                                          t->pid == pid && t->pid_start_time == pid_start_time);
                                break;
                        case POLKIT_AUTHORIZATION_SCOPE_SESSION:
                                kit_assert ((s = polkit_authorization_scope_session_get_ck_objref (a)) != NULL &&
                                          strcmp (s, t->session) == 0);
                                break;
                        case POLKIT_AUTHORIZATION_SCOPE_ALWAYS:
                                break;
                        }

                        kit_assert ((s = _polkit_authorization_get_authfile_entry (a)) != NULL && strcmp (t->entry, s) == 0);

                        kit_assert ((s = polkit_authorization_get_action_id (a)) != NULL && strcmp (t->action_id, s) == 0);

                        kit_assert (t->time_of_grant == polkit_authorization_get_time_of_grant (a));

                        kit_assert ((ac = polkit_authorization_get_constraint (a)) != NULL &&
                                  polkit_authorization_constraint_equal (ac, t->constraint));

                        if (t->explicit) {
                                kit_assert (!polkit_authorization_was_granted_via_defaults (a, &uid));
                                kit_assert (polkit_authorization_was_granted_explicitly (a, &uid) && uid == t->from);
                        } else {
                                kit_assert (polkit_authorization_was_granted_via_defaults (a, &uid) && uid == t->from);
                                kit_assert (!polkit_authorization_was_granted_explicitly (a, &uid));
                        }

                        polkit_authorization_ref (a);
                        polkit_authorization_unref (a);
                        polkit_authorization_unref (a);
                }
        }

        for (n = 0; n < num_invalid_auths; n++) {
                kit_assert (_polkit_authorization_new_for_uid (invalid_auths[n], 500) == NULL);
        }

        return TRUE;
}

#else /* POLKIT_AUTHDB_DEFAULT */

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

#endif /* POLKIT_AUTHDB_DEFAULT */

KitTest _test_authorization = {
        "polkit_authorization",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

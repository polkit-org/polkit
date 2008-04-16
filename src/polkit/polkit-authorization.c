/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-authorization.c : Represents an entry in the authorization
 * database
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
        KitList *constraints;

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


/**
 * polkit_authorization_type:
 * @auth: the authorization object
 *
 * Determine the type of authorization.
 *
 * Returns: the authorization type 
 *
 * Since: 0.7
 */
PolKitAuthorizationType 
polkit_authorization_type (PolKitAuthorization *auth)
{
        return POLKIT_AUTHORIZATION_TYPE_UID;
}

#ifdef POLKIT_AUTHDB_DEFAULT

typedef struct {
        int cur_attr;
        int req_attr;

        int cur_token;
        PolKitAuthorization *auth;
} EntryParserData;

enum {
        ATTR_PID            = 1<<0,
        ATTR_PID_START_TIME = 1<<1,
        ATTR_SESSION_ID     = 1<<2,
        ATTR_ACTION_ID      = 1<<3,
        ATTR_WHEN           = 1<<4,
        ATTR_AUTH_AS        = 1<<5,
        ATTR_GRANTED_BY     = 1<<6,
};

static kit_bool_t
_parse_entry (const char *key, const char *value, void *user_data)
{
        char *ep;
        kit_bool_t ret;
        EntryParserData *epd = (EntryParserData *) user_data;
        PolKitAuthorization *auth = epd->auth;

        ret = FALSE;

        /* scope needs to be first and there can only be only instance of it */
        if (strcmp (key, "scope") == 0) {
                if (epd->cur_token != 0)
                        goto error;

                if (strcmp (value, "process-one-shot") == 0) {
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT;
                        epd->req_attr = ATTR_PID | ATTR_PID_START_TIME | ATTR_ACTION_ID | ATTR_WHEN | ATTR_AUTH_AS;
                } else if (strcmp (value, "process") == 0) {
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_PROCESS;
                        epd->req_attr = ATTR_PID | ATTR_PID_START_TIME | ATTR_ACTION_ID | ATTR_WHEN | ATTR_AUTH_AS;
                } else if (strcmp (value, "session") == 0) {
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_SESSION;
                        epd->req_attr = ATTR_SESSION_ID | ATTR_ACTION_ID | ATTR_WHEN | ATTR_AUTH_AS;
                } else if (strcmp (value, "always") == 0) {
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;
                        epd->req_attr = ATTR_ACTION_ID | ATTR_WHEN | ATTR_AUTH_AS;
                } else if (strcmp (value, "grant") == 0) {
                        auth->explicitly_granted = TRUE;
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;
                        epd->req_attr = ATTR_ACTION_ID | ATTR_WHEN | ATTR_GRANTED_BY;
                } else if (strcmp (value, "grant-negative") == 0) {
                        auth->is_negative = TRUE;
                        auth->explicitly_granted = TRUE;
                        auth->scope = POLKIT_AUTHORIZATION_SCOPE_ALWAYS;
                        epd->req_attr = ATTR_ACTION_ID | ATTR_WHEN | ATTR_GRANTED_BY;
                } else {
                        goto error;
                }

        } else if (strcmp (key, "pid") == 0) {

                if (epd->cur_attr & ATTR_PID)
                        goto error;
                epd->cur_attr |= ATTR_PID;

                auth->pid = strtoul (value, &ep, 10);
                if (strlen (value) == 0 || *ep != '\0')
                        goto error;

        } else if (strcmp (key, "pid-start-time") == 0) {

                if (epd->cur_attr & ATTR_PID_START_TIME)
                        goto error;
                epd->cur_attr |= ATTR_PID_START_TIME;

                auth->pid_start_time = strtoull (value, &ep, 10);
                if (strlen (value) == 0 || *ep != '\0')
                        goto error;

        } else if (strcmp (key, "session-id") == 0) {

                if (epd->cur_attr & ATTR_SESSION_ID)
                        goto error;
                epd->cur_attr |= ATTR_SESSION_ID;

                auth->session_id = kit_strdup (value);
                if (auth->session_id == NULL)
                        goto error;

        } else if (strcmp (key, "action-id") == 0) {

                if (epd->cur_attr & ATTR_ACTION_ID)
                        goto error;
                epd->cur_attr |= ATTR_ACTION_ID;

                if (!polkit_action_validate_id (value))
                        goto error;
                auth->action_id = kit_strdup (value);
                if (auth->action_id == NULL)
                        goto error;

        } else if (strcmp (key, "when") == 0) {

                if (epd->cur_attr & ATTR_WHEN)
                        goto error;
                epd->cur_attr |= ATTR_WHEN;

                auth->when = strtoull (value, &ep, 10);
                if (strlen (value) == 0 || *ep != '\0')
                        goto error;

        } else if (strcmp (key, "auth-as") == 0) {

                if (epd->cur_attr & ATTR_AUTH_AS)
                        goto error;
                epd->cur_attr |= ATTR_AUTH_AS;

                auth->authenticated_as_uid = strtoul (value, &ep, 10);
                if (strlen (value) == 0 || *ep != '\0')
                        goto error;

        } else if (strcmp (key, "granted-by") == 0) {

                if (epd->cur_attr & ATTR_GRANTED_BY)
                        goto error;
                epd->cur_attr |= ATTR_GRANTED_BY;

                auth->explicitly_granted_by = strtoul (value, &ep, 10);
                if (strlen (value) == 0 || *ep != '\0')
                        goto error;

        } else if (strcmp (key, "constraint") == 0) {
                PolKitAuthorizationConstraint *c;
                KitList *l;

                c = polkit_authorization_constraint_from_string (value);
                if (c == NULL)
                        goto error;

                l = kit_list_append (auth->constraints, c);
                if (l == NULL)
                        goto error;
                auth->constraints = l;
        }

        ret = TRUE;

error:
        epd->cur_token += 1;
        return ret;
}

PolKitAuthorization *
_polkit_authorization_new_for_uid (const char *entry_in_auth_file, uid_t uid)
{
        PolKitAuthorization *auth;
        EntryParserData epd;

        kit_return_val_if_fail (entry_in_auth_file != NULL, NULL);

        auth = kit_new0 (PolKitAuthorization, 1);
        if (auth == NULL) {
                goto oom;
        }

        auth->refcount = 1;
        auth->entry_in_auth_file = kit_strdup (entry_in_auth_file);
        if (auth->entry_in_auth_file == NULL)
                goto oom;

        auth->uid = uid;

        epd.auth = auth;
        epd.cur_token = 0;
        epd.cur_attr = 0;
        epd.req_attr = 0;
        if (!kit_string_entry_parse (entry_in_auth_file, _parse_entry, &epd)) {
                goto error;
        }

        /* check that we have all core attributes */
        if (epd.cur_attr != epd.req_attr) {
                goto error;
        }

        return auth;

error:
        //g_warning ("Error parsing token %d from line '%s'", n, entry_in_auth_file);
oom:
        if (auth != NULL)
                polkit_authorization_unref (auth);
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
        KitList *l;

        kit_return_if_fail (auth != NULL);
        auth->refcount--;
        if (auth->refcount > 0) 
                return;

        kit_free (auth->entry_in_auth_file);
        kit_free (auth->action_id);
        kit_free (auth->session_id);

        for (l = auth->constraints; l != NULL; l = l->next) {
                PolKitAuthorizationConstraint *c = (PolKitAuthorizationConstraint *) l->data;
                polkit_authorization_constraint_unref (c);
        }
        if (auth->constraints != NULL)
                kit_list_free (auth->constraints);

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
        polkit_debug ("PolKitAuthorization: refcount=%d", auth->refcount);
        polkit_debug (" scope          = %d",  auth->scope);
        polkit_debug (" pid            = %d",  auth->pid);
        polkit_debug (" pid_start_time = %Lu", auth->pid_start_time);
        polkit_debug (" action_id      = %s",  auth->action_id);
        polkit_debug (" when           = %Lu", (polkit_uint64_t) auth->when);
        polkit_debug (" auth_as_uid    = %d",  auth->authenticated_as_uid);
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
 * constraints, see polkit_authorization_constraints_foreach() for
 * details.
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
 * polkit_authorization_constraints_foreach:
 * @auth: the object
 * @cb: callback function
 * @user_data: user data
 *
 * Iterate over all constraints associated with an authorization.
 *
 * Returns: %TRUE if the caller short-circuited the iteration.
 *
 * Since: 0.7
 */ 
polkit_bool_t
polkit_authorization_constraints_foreach (PolKitAuthorization *auth, 
                                          PolKitAuthorizationConstraintsForeachFunc cb, 
                                          void *user_data)
{
        KitList *i;

        kit_return_val_if_fail (auth != NULL, TRUE);
        kit_return_val_if_fail (cb != NULL, TRUE);

        for (i = auth->constraints; i != NULL; i = i->next) {
                PolKitAuthorizationConstraint *c = i->data;

                if (cb (auth, c, user_data))
                        return TRUE;
        }

        return FALSE;
}

#ifdef POLKIT_BUILD_TESTS

#ifdef POLKIT_AUTHDB_DEFAULT

typedef struct {
        const char *entry;
        PolKitAuthorizationType type;
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
                "scope=non-existant",

                /* wrong number of items */
                "scope=process-one-shot",
                "scope=process",
                "scope=session",
                "scope=always",
                "scope=grant",
                "scope=grant-negative",

                /* repetition of core attributes */
                "scope=process:pid=1:pid=2",
                "scope=process:pid-start-time=1:pid-start-time=2",
                "scope=process:session-id=1:session-id=2",
                "scope=process:action-id=org.foo:action-id=org.bar",
                "scope=process:when=1:when=2",
                "scope=process:auth-as=1:auth-as=2",
                "scope=process:granted-by=1:granted-by=2",

                /* malformed components */
                "scope=process:pid=14485xyz:pid-start-time=26817340:action-id=org.gnome.policykit.examples.frobnicate:when=1194631763:auth-as=500:constraint=local",
                "scope=process:pid=14485:pid-start-time=26817340xyz:action-id=org.gnome.policykit.examples.frobnicate:when=1194631763:auth-as=500:constraint=local",
                "scope=process:pid=14485:pid-start-time=26817340:0xyaction-id=org.gnome.policykit.examples.frobnicate:when=1194631763:auth-as=500:constraint=local",
                "scope=process:pid=14485:pid-start-time=26817340:action-id=org.gnome.policykit.examples.frobnicate:when=1194631763xyz:auth-as=500:constraint=local",
                "scope=process:pid=14485:pid-start-time=26817340:action-id=org.gnome.policykit.examples.frobnicate:when=1194631763:500xyz:constraint=local",
                "scope=process:pid=14485:pid-start-time=26817340:action-id=org.gnome.policykit.examples.frobnicate:when=1194631763:auth-as=500:constraint=MALFORMED_CONSTRAINT",

                /* TODO: validate ConsoleKit paths
                   "scope=session:xyz/org/freedesktop/ConsoleKit/Session1:action-id=org.gnome.policykit.examples.punch:1194631779:auth-as=500:constraint=local",*/
                "scope=session:/org/freedesktop/ConsoleKit/Session1:0xyaction-id=org.gnome.policykit.examples.punch:1194631779:auth-as=500:constraint=local",
                "scope=session:/org/freedesktop/ConsoleKit/Session1:action-id=org.gnome.policykit.examples.punch:1194631779xyz:auth-as=500:constraint=local",
                "scope=session:/org/freedesktop/ConsoleKit/Session1:action-id=org.gnome.policykit.examples.punch:1194631779:500xyz:constraint=local",
                "scope=session:/org/freedesktop/ConsoleKit/Session1:action-id=org.gnome.policykit.examples.punch:1194631779:auth-as=500:constraint=MALFORMED",

                "scope=always:action-id=0xyorg.gnome.clockapplet.mechanism.settimezone:when=1193598494:auth-as=500:constraint=local",
                "scope=always:action-id=org.gnome.clockapplet.mechanism.settimezone:when=xyz1193598494:auth-as=500:constraint=local",
                "scope=always:action-id=org.gnome.clockapplet.mechanism.settimezone:when=1193598494:auth-as=xyz500:constraint=local",
                "scope=always:action-id=org.gnome.clockapplet.mechanism.settimezone:when=1193598494:auth-as=500:constraint=MALFORMED",

                "scope=grant:action-id=0xyorg.freedesktop.policykit.read:when=1194634242:granted-by=0:constraint=none",
                "scope=grant:action-id=org.freedesktop.policykit.read:when=xyz1194634242:granted-by=0:constraint=none",
                "scope=grant:action-id=org.freedesktop.policykit.read:when=1194634242:granted-by=xyz0:constraint=none",
                "scope=grant:action-id=org.freedesktop.policykit.read:when=1194634242:granted-by=0:constraint=MALFORMED",

                "random-future-key=some-value:scope=always:action-id=org.gnome.clockapplet.mechanism.settimezone:when=1193598494:auth-as500:constraint=local",

        };
        size_t num_invalid_auths = sizeof (invalid_auths) / sizeof (const char *);
        TestAuth valid_auths[] = {
                {
                        "scope=always:action-id=org.gnome.clockapplet.mechanism.settimezone:when=1193598494:auth-as=500",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
                        "org.gnome.clockapplet.mechanism.settimezone",
                        1193598494,
                        0, 0, NULL,
                        NULL,
                        FALSE, 500
                },

                {
                        "scope=process:pid=14485:pid-start-time=26817340:action-id=org.gnome.policykit.examples.frobnicate:when=1194631763:auth-as=500",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_PROCESS,
                        "org.gnome.policykit.examples.frobnicate",
                        1194631763,
                        14485, 26817340, NULL,
                        NULL,
                        FALSE, 500
                },

                {
                        "scope=process:pid=14485:pid-start-time=26817340:action-id=org.gnome.policykit.examples.tweak:when=1194631774:auth-as=0",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_PROCESS,
                        "org.gnome.policykit.examples.tweak",
                        1194631774,
                        14485, 26817340, NULL,
                        NULL,
                        FALSE, 0
                },

                {
                        "scope=session:session-id=%2Forg%2Ffreedesktop%2FConsoleKit%2FSession1:action-id=org.gnome.policykit.examples.punch:when=1194631779:auth-as=500",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_SESSION,
                        "org.gnome.policykit.examples.punch",
                        1194631779,
                        0, 0, "/org/freedesktop/ConsoleKit/Session1",
                        NULL,
                        FALSE, 500
                },

                {
                        "scope=process-one-shot:pid=27860:pid-start-time=26974819:action-id=org.gnome.policykit.examples.jump:when=1194633344:auth-as=500",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT,
                        "org.gnome.policykit.examples.jump",
                        1194633344,
                        27860, 26974819, NULL,
                        NULL,
                        FALSE, 500
                },

                {
                        "scope=grant:action-id=org.freedesktop.policykit.read:when=1194634242:granted-by=0",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
                        "org.freedesktop.policykit.read",
                        1194634242,
                        0, 0, NULL,
                        NULL,
                        TRUE, 0
                },

                /* this test ensures we can add new key/value pairs in the future */
                {
                        "scope=grant:FUTURE-KEY=FUTURE-VALUE:action-id=org.freedesktop.policykit.read:when=1194634242:granted-by=0",
                        POLKIT_AUTHORIZATION_TYPE_UID,
                        POLKIT_AUTHORIZATION_SCOPE_ALWAYS,
                        "org.freedesktop.policykit.read",
                        1194634242,
                        0, 0, NULL,
                        NULL,
                        TRUE, 0
                },

        };
        size_t num_valid_auths = sizeof (valid_auths) / sizeof (TestAuth);
        unsigned int n;
        pid_t pid;
        polkit_uint64_t pid_start_time;
        const char *s;
        //PolKitAuthorizationConstraint *ac;
        uid_t uid;
        polkit_bool_t is_neg;

        for (n = 0; n < num_valid_auths; n++) {
                PolKitAuthorization *a;
                TestAuth *t = &(valid_auths[n]);

                if ((a = _polkit_authorization_new_for_uid (t->entry, 500)) != NULL) {

                        polkit_authorization_debug (a);
                        polkit_authorization_validate (a);

                        kit_assert (t->type == polkit_authorization_type (a));
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

                        //TODO:
                        //kit_assert ((ac = polkit_authorization_get_constraint (a)) != NULL &&
                        //          polkit_authorization_constraint_equal (ac, t->constraint));

                        if (t->explicit) {
                                kit_assert (!polkit_authorization_was_granted_via_defaults (a, &uid));
                                kit_assert (polkit_authorization_was_granted_explicitly (a, &uid, &is_neg) && 
                                            uid == t->from && !is_neg);
                        } else {
                                kit_assert (polkit_authorization_was_granted_via_defaults (a, &uid) && uid == t->from);
                                kit_assert (!polkit_authorization_was_granted_explicitly (a, &uid, &is_neg));
                        }

                        polkit_authorization_ref (a);
                        polkit_authorization_unref (a);
                        polkit_authorization_unref (a);
                } else {
                        kit_assert (errno == ENOMEM);
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

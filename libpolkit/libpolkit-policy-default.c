/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-default.c : policy definition for the defaults
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
#include "libpolkit-debug.h"
#include "libpolkit-error.h"
#include "libpolkit-policy-default.h"

/**
 * SECTION:libpolkit-policy-default
 * @short_description: Defaults policy.
 *
 * This class records the default policy of an action.
 **/

/**
 * PolKitPolicyDefault:
 *
 * Objects of this class are used to record information about a
 * default policy for an action.
 **/
struct PolKitPolicyDefault
{
        int refcount;
        PolKitResult default_remote_inactive;
        PolKitResult default_remote_active;
        PolKitResult default_local_inactive;
        PolKitResult default_local_active;
};

static gboolean
parse_default (const char *key, char *s, const char *group, PolKitResult* target, GError **error)
{
        gboolean ret;

        ret = libpolkit_result_from_string_representation (s, target);
        if (!ret) {
                int n;
                char *s2;
                GString *str;

                str = g_string_new (NULL);
                for (n = 0; n < LIBPOLKIT_RESULT_N_RESULTS; n++) {
                        if (n == LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW)
                                continue;

                        if (str->len > 0) {
                                g_string_append (str, ", ");
                        }
                        g_string_append (str, libpolkit_result_to_string_representation (n));
                }
                s2 = g_string_free (str, FALSE);

                g_set_error (error, 
                             POLKIT_ERROR, 
                             POLKIT_ERROR_POLICY_FILE_INVALID,
                             "Value '%s' is not allowed for key '%s' in group '%s' - supported values are: %s", 
                             s, 
                             key,
                             group,
                             s2);
                g_free (s2);
        }
        
        g_free (s);
        return ret;
}

/**
 * libpolkit_policy_default_new:
 * @key_file: a #GKeyFile object
 * @action: action to look up defaults for in key_file
 * @error: return location for error
 * 
 * Create a new #PolKitPolicyDefault object.
 * 
 * Returns: the new object or #NULL if error is set
 **/
PolKitPolicyDefault *
libpolkit_policy_default_new (GKeyFile *key_file, const char *action, GError **error)
{
        const char *key;
        const char *group;
        char *s;
        char buf[256];
        PolKitPolicyDefault *pd;

        pd = g_new0 (PolKitPolicyDefault, 1);
        pd->refcount = 1;

        g_snprintf (buf, sizeof (buf), "Action %s", action);
        group = buf;

        key = "AllowRemoteInactive";
        if ((s = g_key_file_get_string (key_file, group, key, error)) == NULL)
                goto error;
        if (!parse_default (key, s, group, &pd->default_remote_inactive, error))
                goto error;
        key = "AllowRemoteActive";
        if ((s = g_key_file_get_string (key_file, group, key, error)) == NULL)
                goto error;
        if (!parse_default (key, s, group, &pd->default_remote_active, error))
                goto error;
        key = "AllowLocalInactive";
        if ((s = g_key_file_get_string (key_file, group, key, error)) == NULL)
                goto error;
        if (!parse_default (key, s, group, &pd->default_local_inactive, error))
                goto error;
        key = "AllowLocalActive";
        if ((s = g_key_file_get_string (key_file, group, key, error)) == NULL)
                goto error;
        if (!parse_default (key, s, group, &pd->default_local_active, error))
                goto error;

        return pd;
error:
        if (pd != NULL)
                libpolkit_policy_default_ref (pd);
        return NULL;
}

/**
 * libpolkit_policy_default_ref:
 * @policy_default: the policy object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyDefault *
libpolkit_policy_default_ref (PolKitPolicyDefault *policy_default)
{
        g_return_val_if_fail (policy_default != NULL, policy_default);
        policy_default->refcount++;
        return policy_default;
}

/**
 * libpolkit_policy_default_unref:
 * @policy_default: the object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_policy_default_unref (PolKitPolicyDefault *policy_default)
{
        g_return_if_fail (policy_default != NULL);
        policy_default->refcount--;
        if (policy_default->refcount > 0) 
                return;
        g_free (policy_default);
}

/**
 * libpolkit_policy_default_debug:
 * @policy_default: the object
 * 
 * Print debug details
 **/
void
libpolkit_policy_default_debug (PolKitPolicyDefault *policy_default)
{
        g_return_if_fail (policy_default != NULL);
        _pk_debug ("PolKitPolicyDefault: refcount=%d\n"
                   "  default_remote_inactive=%s\n"
                   "    default_remote_active=%s\n"
                   "   default_local_inactive=%s\n"
                   "     default_local_active=%s", 
                   policy_default->refcount,
                   libpolkit_result_to_string_representation (policy_default->default_remote_inactive),
                   libpolkit_result_to_string_representation (policy_default->default_remote_active),
                   libpolkit_result_to_string_representation (policy_default->default_local_inactive),
                   libpolkit_result_to_string_representation (policy_default->default_local_active));
}


/**
 * libpolkit_policy_default_can_session_access_resource:
 * @policy_default: the object
 * @action: the type of access to check for
 * @resource: the resource in question
 * @session: the session in question
 * 
 * Using the default policy for an action, determine if a given
 * session can access a given resource in a given way.
 * 
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
 * #LIBPOLKIT_RESULT_YES, #LIBPOLKIT_RESULT_NO.
 **/
PolKitResult
libpolkit_policy_default_can_session_access_resource (PolKitPolicyDefault *policy_default,
                                                         PolKitAction        *action,
                                                         PolKitResource         *resource,
                                                         PolKitSession          *session)
{
        gboolean is_local;
        gboolean is_active;
        PolKitResult ret;

        ret = LIBPOLKIT_RESULT_NO;

        g_return_val_if_fail (policy_default != NULL, ret);
        g_return_val_if_fail (action != NULL, ret);
        g_return_val_if_fail (resource != NULL, ret);
        g_return_val_if_fail (session != NULL, ret);

        if (!libpolkit_session_get_ck_is_local (session, &is_local))
                goto out;
        if (!libpolkit_session_get_ck_is_active (session, &is_active))
                goto out;

        if (is_local) {
                if (is_active) {
                        ret = policy_default->default_local_active;
                } else {
                        ret = policy_default->default_local_inactive;
                }
        } else {
                if (is_active) {
                        ret = policy_default->default_remote_active;
                } else {
                        ret = policy_default->default_remote_inactive;
                }
        }
out:
        return ret;
}

/**
 * libpolkit_policy_default_can_caller_access_resource:
 * @policy_default: the object
 * @action: the type of access to check for
 * @resource: the resource in question
 * @caller: the resource in question
 * 
 * Using the default policy for an action, determine if a given
 * caller can access a given resource in a given way.
 * 
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * access the resource in the given way
 **/
PolKitResult
libpolkit_policy_default_can_caller_access_resource (PolKitPolicyDefault *policy_default,
                                                        PolKitAction        *action,
                                                        PolKitResource         *resource,
                                                        PolKitCaller           *caller)
{
        gboolean is_local;
        gboolean is_active;
        PolKitSession *session;
        PolKitResult ret;

        ret = LIBPOLKIT_RESULT_NO;

        g_return_val_if_fail (policy_default != NULL, ret);
        g_return_val_if_fail (action != NULL, ret);
        g_return_val_if_fail (resource != NULL, ret);
        g_return_val_if_fail (caller != NULL, ret);

        if (!libpolkit_caller_get_ck_session (caller, &session))
                goto out;
        if (session == NULL)
                goto out;

        if (!libpolkit_session_get_ck_is_local (session, &is_local))
                goto out;
        if (!libpolkit_session_get_ck_is_active (session, &is_active))
                goto out;

        if (is_local) {
                if (is_active) {
                        ret = policy_default->default_local_active;
                } else {
                        ret = policy_default->default_local_inactive;
                }
        } else {
                if (is_active) {
                        ret = policy_default->default_remote_active;
                } else {
                        ret = policy_default->default_remote_inactive;
                }
        }
out:
        return ret;
}

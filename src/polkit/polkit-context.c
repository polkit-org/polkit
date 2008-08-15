/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-context.c : context for PolicyKit
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if HAVE_SOLARIS
#include <sys/stat.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <dirent.h>

#include "polkit-debug.h"
#include "polkit-context.h"
#include "polkit-private.h"
#include "polkit-test.h"

/**
 * SECTION:polkit
 * @short_description: Centralized policy management.
 *
 * libpolkit is a C library for centralized policy management.
 **/

/**
 * SECTION:polkit-context
 * @title: Context
 * @short_description: The main interface used to query PolicyKit.
 *
 * This class is used to represent the interface to PolicyKit - it is
 * used by Mechanisms that use PolicyKit for making
 * decisions. Typically, it's used as a singleton:
 *
 * <itemizedlist>
 * <listitem>First, the Mechanism need to declare one or more PolicyKit Actions by dropping a <literal>.policy</literal> file into <literal>/usr/share/polkit-1/actions</literal>. This is described in the PolicyKit specification.</listitem>
 * <listitem>The mechanism starts up and uses polkit_context_new() to create a new context</listitem>
 * <listitem>If the mechanism is a long running daemon, it should use polkit_context_set_config_changed() to register a callback when configuration changes. This is useful if, for example, the mechanism needs to revise decisions based on earlier answers from libpolkit. For example, a daemon that manages permissions on <literal>/dev</literal> may want to add/remove ACL's when configuration changes.
 * <listitem>If polkit_context_set_config_changed() is used, the mechanism must also use polkit_context_set_io_watch_functions() to integrate libpolkit into the mainloop.</listitem>
 * <listitem>The mechanism needs to call polkit_context_init() such that libpolkit can load configuration files and properly initialize.</listitem>
 * <listitem>Whenever the mechanism needs to make a decision whether a caller is allowed to make a perform some action, the mechanism prepares a #PolKitAction and #PolKitCaller object (or #PolKitSession if applicable) and calls polkit_context_can_caller_do_action() (or polkit_context_can_session_do_action() if applicable). The mechanism may use the libpolkit-dbus library (specifically the polkit_caller_new_from_dbus_name() or polkit_caller_new_from_pid() functions) but may opt, for performance reasons, to construct #PolKitCaller (or #PolKitSession if applicable) from it's own cache of information.</listitem>
 * <listitem>The mechanism will get a #PolKitResult object back that describes whether it should carry out the action. This result stems from a number of sources, see the PolicyKit specification document for details.</listitem>
 * <listitem>If the result is #POLKIT_RESULT_YES, the mechanism should carry out the action. If the result is not #POLKIT_RESULT_YES nor #POLKIT_RESULT_UNKNOWN (this would never be returned but is mentioned here for completeness), the mechanism should throw an expcetion to the caller detailing the #PolKitResult as a textual string using polkit_result_to_string_representation(). For example, if the mechanism is using D-Bus it could throw an com.some-mechanism.DeniedByPolicy exception with the #PolKitResult textual representation in the detail field. Then the caller can interpret this exception and then act on it (for example it can attempt to gain that privilege).</listitem>
 * </itemizedlist>
 *
 * For more information about using PolicyKit in mechanisms and
 * callers, refer to the PolicyKit-gnome project which includes a
 * sample application on how to use this in the GNOME desktop.
 **/

/**
 * PolKitContext:
 *
 * Context object for users of PolicyKit.
 **/
struct _PolKitContext
{
        int refcount;

        PolKitContextConfigChangedCB config_changed_cb;
        void *config_changed_user_data;

        char *policy_dir;

        PolKitAuthorizationDB *authdb;

        KitList *action_descriptions;
};

/**
 * polkit_context_new:
 * 
 * Create a new context
 * 
 * Returns: the object
 **/
PolKitContext *
polkit_context_new (void)
{
        PolKitContext *pk_context;
        pk_context = kit_new0 (PolKitContext, 1);
        pk_context->refcount = 1;
        /* TODO: May want to rethink instantiating this on demand.. */
        pk_context->authdb = _polkit_authorization_db_new ();
        return pk_context;
}

/**
 * polkit_context_init:
 * @pk_context: the context object
 * @error: return location for error
 * 
 * Initializes a new context; loads PolicyKit files from
 * /usr/share/polkit-1/actions.
 *
 * Returns: #FALSE if @error was set, otherwise #TRUE
 **/
polkit_bool_t
polkit_context_init (PolKitContext *pk_context, PolKitError **error)
{

        kit_return_val_if_fail (pk_context != NULL, FALSE);

        pk_context->policy_dir = kit_strdup (PACKAGE_DATA_DIR "/polkit-1/actions");
        polkit_debug ("Using policy files from directory %s", pk_context->policy_dir);

        return TRUE;
        //error:
        //return FALSE;
}

/**
 * polkit_context_ref:
 * @pk_context: the context object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitContext *
polkit_context_ref (PolKitContext *pk_context)
{
        kit_return_val_if_fail (pk_context != NULL, pk_context);
        pk_context->refcount++;
        return pk_context;
}

/**
 * polkit_context_unref:
 * @pk_context: the context object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_context_unref (PolKitContext *pk_context)
{

        kit_return_if_fail (pk_context != NULL);
        pk_context->refcount--;
        if (pk_context->refcount > 0) 
                return;

        kit_free (pk_context);
}

/**
 * polkit_context_set_config_changed:
 * @pk_context: the context object
 * @cb: the callback to invoke
 * @user_data: user data to pass to the callback
 * 
 * Register the callback function for when configuration changes.
 * Mechanisms should use this callback to e.g. reconfigure all
 * permissions / acl's they have set in response to policy decisions
 * made from information provided by PolicyKit. 
 *
 * Note that this function may be called many times within a short
 * interval due to how file monitoring works if e.g. the user is
 * editing a configuration file (editors typically create back-up
 * files). Mechanisms should use a "cool-off" timer (of, say, one
 * second) to avoid doing many expensive operations (such as
 * reconfiguring all ACL's for all devices) within a very short
 * timeframe.
 *
 * This method must be called before polkit_context_init().
 **/
void
polkit_context_set_config_changed (PolKitContext                *pk_context, 
                                   PolKitContextConfigChangedCB  cb, 
                                   void                         *user_data)
{
        kit_return_if_fail (pk_context != NULL);
        pk_context->config_changed_cb = cb;
        pk_context->config_changed_user_data = user_data;
}

/**
 * polkit_context_is_session_authorized:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @session: the session in question
 * @error: return location for error
 *
 * Determine if any caller from a giver session is authorized to do a
 * given action.
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do a specific action. 
 *
 * Since: 0.7
 */
PolKitResult
polkit_context_is_session_authorized (PolKitContext         *pk_context,
                                      PolKitAction          *action,
                                      PolKitSession         *session,
                                      PolKitError          **error)
{
        //PolKitPolicyCache *cache;
        PolKitResult result_from_grantdb;
        polkit_bool_t from_authdb;
        polkit_bool_t from_authdb_negative;
        PolKitResult result;

        result = POLKIT_RESULT_NO;
        kit_return_val_if_fail (pk_context != NULL, result);

        if (action == NULL || session == NULL)
                goto out;

        /* now validate the incoming objects */
        if (!polkit_action_validate (action))
                goto out;
        if (!polkit_session_validate (session))
                goto out;

        //cache = polkit_context_get_policy_cache (pk_context);
        //if (cache == NULL)
        //        goto out;

        result_from_grantdb = POLKIT_RESULT_UNKNOWN;
        from_authdb_negative = FALSE;
        if (polkit_authorization_db_is_session_authorized (pk_context->authdb, 
                                                           action, 
                                                           session,
                                                           &from_authdb,
                                                           &from_authdb_negative,
                                                           NULL /* TODO */)) {
                if (from_authdb)
                        result_from_grantdb = POLKIT_RESULT_YES;
        }

        /* If we have a positive answer from the authdb, use it */
        if (result_from_grantdb == POLKIT_RESULT_YES) {
                result = POLKIT_RESULT_YES;
                goto found;
        }

        /* Otherwise, unless we found a negative auth, fall back to defaults as specified in the .policy file */
        if (!from_authdb_negative) {
                PolKitActionDescription *pfe;

                pfe = NULL; //pfe = polkit_policy_cache_get_entry (cache, action);
                if (pfe != NULL) {
                        PolKitImplicitAuthorization *implicit_authorization;

                        implicit_authorization = polkit_action_description_get_implicit_authorization (pfe);
                        if (implicit_authorization != NULL) {
                                result = polkit_implicit_authorization_can_session_do_action (implicit_authorization, action, session);
                        }
                }
        }

found:
        /* Never return UNKNOWN to user */
        if (result == POLKIT_RESULT_UNKNOWN)
                result = POLKIT_RESULT_NO;

out:
        polkit_debug ("... result was %s", polkit_result_to_string_representation (result));
        return result;
}

/**
 * polkit_context_is_caller_authorized:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @caller: the caller in question
 * @revoke_if_one_shot: Whether to revoke one-shot authorizations. See
 * below for discussion.
 * @error: return location for error
 *
 * Determine if a given caller is authorized to do a given
 * action. 
 *
 * It is important to understand how one-shot authorizations work.
 * The revoke_if_one_shot parameter, if #TRUE, specifies whether
 * one-shot authorizations should be revoked if they are used
 * to make the decision to return #POLKIT_RESULT_YES.
 *
 * UI applications wanting to hint whether a caller is authorized must
 * pass #FALSE here. Mechanisms that wants to check authorizations
 * before carrying out work on behalf of a caller must pass #TRUE
 * here.
 *
 * As a side-effect, any process with the authorization
 * org.freedesktop.policykit.read can revoke one-shot authorizations
 * from other users. Even though the window for doing so is small
 * (one-shot auths are typically used right away), be careful who you
 * grant that authorization to.
 *
 * This can fail with the following errors: 
 * #POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do a specific action. 
 *
 * Since: 0.7
 */
PolKitResult
polkit_context_is_caller_authorized (PolKitContext         *pk_context,
                                     PolKitAction          *action,
                                     PolKitCaller          *caller,
                                     polkit_bool_t          revoke_if_one_shot,
                                     PolKitError          **error)
{
        //PolKitPolicyCache *cache;
        PolKitResult result;
        PolKitResult result_from_grantdb;
        polkit_bool_t from_authdb;
        polkit_bool_t from_authdb_negative;

        result = POLKIT_RESULT_NO;
        kit_return_val_if_fail (pk_context != NULL, result);

        if (action == NULL || caller == NULL)
                goto out;

        //cache = polkit_context_get_policy_cache (pk_context);
        //if (cache == NULL)
        //       goto out;

        /* now validate the incoming objects */
        if (!polkit_action_validate (action))
                goto out;
        if (!polkit_caller_validate (caller))
                goto out;

        result_from_grantdb = POLKIT_RESULT_UNKNOWN;
        from_authdb_negative = FALSE;
        if (polkit_authorization_db_is_caller_authorized (pk_context->authdb, 
                                                          action, 
                                                          caller,
                                                          revoke_if_one_shot,
                                                          &from_authdb,
                                                          &from_authdb_negative, 
                                                          NULL /* TODO */)) {
                if (from_authdb)
                        result_from_grantdb = POLKIT_RESULT_YES;
        }

        /* If we have a positive answer from the authdb, use it */
        if (result_from_grantdb == POLKIT_RESULT_YES) {
                result = POLKIT_RESULT_YES;
                goto found;
        }

        /* Otherwise, unless we found a negative auth, fall back to defaults as specified in the .policy file */
        if (!from_authdb_negative) {
                PolKitActionDescription *pfe;

                pfe = NULL; //pfe = polkit_policy_cache_get_entry (cache, action);
                if (pfe != NULL) {
                        PolKitImplicitAuthorization *implicit_authorization;

                        implicit_authorization = polkit_action_description_get_implicit_authorization (pfe);
                        if (implicit_authorization != NULL) {
                                result = polkit_implicit_authorization_can_caller_do_action (implicit_authorization, action, caller);
                        }
                }
        }

found:

        /* Never return UNKNOWN to user */
        if (result == POLKIT_RESULT_UNKNOWN)
                result = POLKIT_RESULT_NO;
out:
        polkit_debug ("... result was %s", polkit_result_to_string_representation (result));
        return result;
}

/**
 * polkit_context_get_authorization_db:
 * @pk_context: the PolicyKit context
 * 
 * Returns an object that provides access to the authorization
 * database. Applications using PolicyKit should never use this
 * method; it's only here for integration with other PolicyKit
 * components.
 *
 * Returns: A #PolKitAuthorizationDB object. Caller should not unref
 * this object.
 */
PolKitAuthorizationDB *
polkit_context_get_authorization_db (PolKitContext *pk_context)
{
        return pk_context->authdb;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_context = {
        "polkit_context",
        NULL,
        NULL,
        _run_test
};


#endif /* POLKIT_BUILD_TESTS */


static polkit_bool_t
_prepend_entry (PolKitActionDescription  *action_description,
                void                   *user_data)
{
        KitList *l;
        PolKitContext *pk_context = user_data;

        polkit_action_description_ref (action_description);
        l = kit_list_prepend (pk_context->action_descriptions, action_description);
        if (l == NULL) {
                polkit_action_description_unref (action_description);
                goto oom;
        }
        pk_context->action_descriptions = l;
        return FALSE;
oom:
        return TRUE;
}

static void
get_descriptions (PolKitContext  *pk_context, PolKitError **error)
{
        DIR *dir;
#ifdef HAVE_READDIR64
        struct dirent64 *d;
#else
	struct dirent *d;
#endif
        struct stat statbuf;
        const char *dirname = PACKAGE_DATA_DIR "/polkit-1/actions";

        dir = NULL;

        dir = opendir (dirname);
        if (dir == NULL) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Cannot load policy files from directory %s: %m",
                                        dirname);
                goto out;
        }

#ifdef HAVE_READDIR64
        while ((d = readdir64 (dir)) != NULL) {
#else
	while ((d = readdir (dir)) != NULL) {
#endif
                char *path;
                PolKitError *pk_error;
                size_t name_len;
                char *filename;
                static const char suffix[] = ".policy";

                path = kit_strdup_printf ("%s/%s", dirname, d->d_name);
                if (path == NULL) {
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY, "Out of memory");
                        goto out;
                }

                if (stat (path, &statbuf) != 0)  {
                        polkit_error_set_error (error, POLKIT_ERROR_GENERAL_ERROR, "stat()");
                        kit_free (path);
                        goto out;
                }
                
                if (!S_ISREG (statbuf.st_mode)) {
                        kit_free (path);
                        continue;
                }

                filename = d->d_name;
                name_len = strlen (filename);
                if (name_len < sizeof (suffix) || strcmp ((filename + name_len - sizeof (suffix) + 1), suffix) != 0) {
                        kit_free (path);
                        continue;
                }

                polkit_debug ("Loading %s", path);
                pk_error = NULL;

                if (polkit_action_description_get_from_file (path, _prepend_entry, pk_context, &pk_error)) {
                        /* OOM failure from _prepend_entry */
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY, "Out of memory");
                        goto out;
                }

                if (polkit_error_is_set (pk_error)) {
                        if (polkit_error_get_error_code (pk_error) == POLKIT_ERROR_OUT_OF_MEMORY) {
                                if (error != NULL)
                                        *error = pk_error;
                                else
                                        polkit_error_free (pk_error);
                                goto out;
                        }

                        kit_warning ("ignoring malformed policy file: %s",
                                     polkit_error_get_error_message (pk_error));
                        polkit_error_free (pk_error);
                }

        }
        closedir (dir);

        return;

out:
        if (dir != NULL)
                closedir(dir);
}

static void
ensure_descriptions (PolKitContext  *pk_context)
{
        PolKitError *error;
        error = NULL;

        if (pk_context->action_descriptions != NULL)
                goto out;

        get_descriptions (pk_context, &error);
        if (polkit_error_is_set (error)) {
                kit_warning ("Error loading policy files: %s: %s",
                             polkit_error_get_error_name (error),
                             polkit_error_get_error_message (error));
                polkit_error_free (error);
                goto out;
        }

 out:
        ;
}

polkit_bool_t
polkit_context_action_description_foreach (PolKitContext                      *pk_context,
                                           PolKitActionDescriptionForeachFunc  cb,
                                           void                               *user_data)
{
        KitList *l;
        polkit_bool_t short_circuit;

        ensure_descriptions (pk_context);

        short_circuit = FALSE;
        for (l = pk_context->action_descriptions; l != NULL; l = l->next) {
                PolKitActionDescription *action_description = l->data;

                if (cb (action_description, user_data)) {
                        short_circuit = TRUE;
                        break;
                }
        }

        return short_circuit;
}

PolKitActionDescription *
polkit_context_get_action_description (PolKitContext   *pk_context,
                                       const char      *action_id)
{
        KitList *l;
        PolKitActionDescription *action_description;

        ensure_descriptions (pk_context);

        action_description = NULL;

        for (l = pk_context->action_descriptions; l != NULL; l = l->next) {
                PolKitActionDescription *ad = l->data;
                if (strcmp (polkit_action_description_get_id (ad), action_id) == 0) {
                        action_description = ad;
                        break;
                }
        }

        return action_description;
}

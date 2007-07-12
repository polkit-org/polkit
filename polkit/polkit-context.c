/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-context.c : context for PolicyKit
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
#include <sys/inotify.h>

#include <glib.h>
#include "polkit-debug.h"
#include "polkit-context.h"
#include "polkit-policy-cache.h"

/**
 * SECTION:polkit
 * @short_description: Centralized policy management.
 *
 * polkit is a C library for centralized policy management.
 **/

/**
 * SECTION:polkit-context
 * @short_description: Context.
 *
 * This class is used to represent the interface to PolicyKit.
 **/

/**
 * PolKitContext:
 *
 * Context object for users of PolicyKit.
 **/
struct PolKitContext
{
        int refcount;

        PolKitContextConfigChangedCB config_changed_cb;
        void *config_changed_user_data;

        PolKitContextAddIOWatch      io_add_watch_func;
        PolKitContextRemoveIOWatch   io_remove_watch_func;

        char *policy_dir;

        PolKitPolicyCache *priv_cache;

        polkit_bool_t load_descriptions;

        int inotify_fd;
        int inotify_fd_watch_id;

        int inotify_reload_wd;
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
        pk_context = g_new0 (PolKitContext, 1);
        pk_context->refcount = 1;
        return pk_context;
}
/**
 * polkit_context_init:
 * @pk_context: the context object
 * @error: return location for error
 * 
 * Initializes a new context; loads PolicyKit files from
 * /usr/share/PolicyKit/policy unless the environment variable
 * $POLKIT_POLICY_DIR points to another location.
 *
 * Returns: #FALSE if @error was set, otherwise #TRUE
 **/
polkit_bool_t
polkit_context_init (PolKitContext *pk_context, PolKitError **error)
{
        const char *dirname;

        dirname = getenv ("POLKIT_POLICY_DIR");
        if (dirname != NULL) {
                pk_context->policy_dir = g_strdup (dirname);
        } else {
                pk_context->policy_dir = g_strdup (PACKAGE_DATA_DIR "/PolicyKit/policy");
        }
        _pk_debug ("Using policy files from directory %s", pk_context->policy_dir);

        /* we don't populate the cache until it's needed.. */
        if (pk_context->io_add_watch_func != NULL) {
                pk_context->inotify_fd = inotify_init ();
                if (pk_context->inotify_fd < 0) {
                        _pk_debug ("failed to initialize inotify: %s", strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

                /* create a watch on /var/lib/PolicyKit/reload */
                pk_context->inotify_reload_wd = inotify_add_watch (pk_context->inotify_fd, 
                                                                   PACKAGE_LOCALSTATEDIR "/lib/PolicyKit/reload", 
                                                                   IN_MODIFY | IN_CREATE | IN_ATTRIB);
                if (pk_context->inotify_reload_wd < 0) {
                        _pk_debug ("failed to add watch on file '" PACKAGE_LOCALSTATEDIR "/lib/PolicyKit/reload': %s",
                                   strerror (errno));
                        /* TODO: set error */
                        goto error;
                }

                pk_context->inotify_fd_watch_id = pk_context->io_add_watch_func (pk_context, pk_context->inotify_fd);
                if (pk_context->inotify_fd_watch_id == 0) {
                        _pk_debug ("failed to add io watch");
                        /* TODO: set error */
                        goto error;
                }
        }

        return TRUE;

error:
        if (pk_context != NULL)
                polkit_context_unref (pk_context);

        return FALSE;
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
        g_return_val_if_fail (pk_context != NULL, pk_context);
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

        g_return_if_fail (pk_context != NULL);
        pk_context->refcount--;
        if (pk_context->refcount > 0) 
                return;

        g_free (pk_context);
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
        g_return_if_fail (pk_context != NULL);
        pk_context->config_changed_cb = cb;
        pk_context->config_changed_user_data = user_data;
}

/**
 * polkit_context_io_func:
 * @pk_context: the object
 * @fd: the file descriptor passed to the supplied function of type #PolKitContextAddIOWatch.
 * 
 * Method that the application must call when there is data to read
 * from a file descriptor registered with the supplied function of
 * type #PolKitContextAddIOWatch.
 **/
void 
polkit_context_io_func (PolKitContext *pk_context, int fd)
{
        g_return_if_fail (pk_context != NULL);

        _pk_debug ("polkit_context_io_func: data on fd %d", fd);

        if (fd == pk_context->inotify_fd) {
/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))
/* reasonable guess as to size of 1024 events */
#define BUF_LEN        (1024 * (EVENT_SIZE + 16))
                char buf[BUF_LEN];
                int len;
                int i = 0;
again:
                len = read (fd, buf, BUF_LEN);
                if (len < 0) {
                        if (errno == EINTR) {
                                goto again;
                        } else {
                                _pk_debug ("read: %s", strerror (errno));
                        }
                } else if (len > 0) {
                        /* BUF_LEN too small? */
                }
                while (i < len) {
                        struct inotify_event *event;
                        event = (struct inotify_event *) &buf[i];
                        _pk_debug ("wd=%d mask=%u cookie=%u len=%u",
                                   event->wd, event->mask, event->cookie, event->len);

                        if (event->wd == pk_context->inotify_reload_wd) {
                                _pk_debug ("config changed!");
                                if (pk_context->config_changed_cb != NULL) {
                                        pk_context->config_changed_cb (pk_context, 
                                                                       pk_context->config_changed_user_data);
                                }
                        }

                        i += EVENT_SIZE + event->len;
                }
        }
}

/**
 * polkit_context_set_io_watch_functions:
 * @pk_context: the context object
 * @io_add_watch_func: the function that the PolicyKit library can invoke to start watching a file descriptor
 * @io_remove_watch_func: the function that the PolicyKit library can invoke to stop watching a file descriptor
 * 
 * Register a functions that PolicyKit can use for watching IO descriptors.
 *
 * This method must be called before polkit_context_init().
 **/
void
polkit_context_set_io_watch_functions (PolKitContext                        *pk_context, 
                                       PolKitContextAddIOWatch               io_add_watch_func,
                                       PolKitContextRemoveIOWatch            io_remove_watch_func)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->io_add_watch_func = io_add_watch_func;
        pk_context->io_remove_watch_func = io_remove_watch_func;
}

/**
 * polkit_context_set_load_descriptions:
 * @pk_context: the context
 * 
 * Set whether policy descriptions should be loaded. By default these
 * are not loaded to keep memory use down. 
 *
 * This method must be called before polkit_context_init().
 **/
void
polkit_context_set_load_descriptions  (PolKitContext *pk_context)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->load_descriptions = TRUE;
}

extern PolKitPolicyCache     *_polkit_policy_cache_new       (const char *dirname, polkit_bool_t load_descriptions, PolKitError **error);

/**
 * polkit_context_get_policy_cache:
 * @pk_context: the context
 * 
 * Get the #PolKitPolicyCache object that holds all the defined policies as well as their defaults.
 * 
 * Returns: the #PolKitPolicyCache object. Caller shall not unref it.
 **/
PolKitPolicyCache *
polkit_context_get_policy_cache (PolKitContext *pk_context)
{
        g_return_val_if_fail (pk_context != NULL, NULL);

        if (pk_context->priv_cache == NULL) {
                PolKitError *error;

                _pk_debug ("Populating cache from directory %s", pk_context->policy_dir);

                error = NULL;
                pk_context->priv_cache = _polkit_policy_cache_new (pk_context->policy_dir, 
                                                                   pk_context->load_descriptions, 
                                                                   &error);
                if (pk_context->priv_cache == NULL) {
                        g_warning ("Error loading policy files from %s: %s", 
                                   pk_context->policy_dir, polkit_error_get_error_message (error));
                        polkit_error_free (error);
                } else {
                        polkit_policy_cache_debug (pk_context->priv_cache);
                }
        }

        return pk_context->priv_cache;
}

/**
 * polkit_context_can_session_do_action:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @session: the session in question
 *
 * Determine if a given session can do a given action.
 *
 * Returns: A #PolKitResult - can only be one of
 * #POLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
 * #POLKIT_RESULT_YES, #POLKIT_RESULT_NO.
 */
PolKitResult
polkit_context_can_session_do_action (PolKitContext   *pk_context,
                                      PolKitAction    *action,
                                      PolKitSession   *session)
{
        PolKitPolicyCache *cache;
        PolKitPolicyFileEntry *pfe;
        PolKitResult current_result;

        current_result = POLKIT_RESULT_NO;
        g_return_val_if_fail (pk_context != NULL, current_result);

        if (action == NULL || session == NULL)
                goto out;

        /* now validate the incoming objects */
        if (!polkit_action_validate (action))
                goto out;
        if (!polkit_session_validate (session))
                goto out;

        cache = polkit_context_get_policy_cache (pk_context);
        if (cache == NULL)
                goto out;

        _pk_debug ("entering polkit_can_session_do_action()");
        polkit_action_debug (action);
        polkit_session_debug (session);

        pfe = polkit_policy_cache_get_entry (cache, action);
        if (pfe == NULL) {
                char *action_name;
                if (!polkit_action_get_action_id (action, &action_name)) {
                        g_warning ("given action has no name");
                } else {
                        g_warning ("no action with name '%s'", action_name);
                }
                current_result = POLKIT_RESULT_UNKNOWN_ACTION;
                goto out;
        }

        polkit_policy_file_entry_debug (pfe);

        current_result = POLKIT_RESULT_UNKNOWN_ACTION;

#if 0
        /* visit modules */
        for (i = pk_context->modules; i != NULL; i = g_slist_next (i)) {
                PolKitModuleInterface *module_interface = i->data;
                PolKitModuleCanSessionDoAction func;

                func = polkit_module_get_func_can_session_do_action (module_interface);
                if (func != NULL) {
                        PolKitModuleControl module_control;
                        PolKitResult module_result;

                        _pk_debug ("Asking module '%s'", polkit_module_get_name (module_interface));

                        module_control = polkit_module_interface_get_control (module_interface);

                        if (polkit_module_interface_check_builtin_confinement_for_session (
                                    module_interface,
                                    pk_context,
                                    action,
                                    session)) {
                                /* module is confined by built-in options */
                                module_result = POLKIT_RESULT_UNKNOWN_ACTION;
                                _pk_debug ("Module '%s' confined by built-in's", 
                                           polkit_module_get_name (module_interface));
                        } else {
                                module_result = func (module_interface,
                                                      pk_context,
                                                      action, 
                                                      session);
                        }

                        /* if a module returns _UNKNOWN_ACTION, it means that it doesn't
                         * have an opinion about the query; e.g. polkit-module-allow-all(8)
                         * will return this if it's confined to only consider certain actions
                         * or certain users.
                         */
                        if (module_result != POLKIT_RESULT_UNKNOWN_ACTION) {

                                if (current_control == POLKIT_MODULE_CONTROL_ADVISE &&
                                    module_control == POLKIT_MODULE_CONTROL_ADVISE) {

                                        /* take the less strict result */
                                        if (current_result < module_result) {
                                                current_result = module_result;
                                        }

                                } else if (current_control == POLKIT_MODULE_CONTROL_ADVISE &&
                                           module_control == POLKIT_MODULE_CONTROL_MANDATORY) {
                                        
                                        /* here we just override */
                                        current_result = module_result;

                                        /* we are now in mandatory mode */
                                        current_control = POLKIT_MODULE_CONTROL_MANDATORY;
                                }
                        }
                }
        }
#endif

        /* Never return UNKNOWN_ACTION to user */
        if (current_result == POLKIT_RESULT_UNKNOWN_ACTION)
                current_result = POLKIT_RESULT_NO;

out:
        _pk_debug ("... result was %s", polkit_result_to_string_representation (current_result));
        return current_result;
}

/**
 * polkit_context_can_caller_do_action:
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @caller: the caller in question
 *
 * Determine if a given caller can do a given action.
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * do a specific action
 */
PolKitResult
polkit_context_can_caller_do_action (PolKitContext   *pk_context,
                                     PolKitAction    *action,
                                     PolKitCaller    *caller)
{
        PolKitPolicyCache *cache;
        PolKitPolicyFileEntry *pfe;
        PolKitResult current_result;

        current_result = POLKIT_RESULT_NO;
        g_return_val_if_fail (pk_context != NULL, current_result);

        if (action == NULL || caller == NULL)
                goto out;

        cache = polkit_context_get_policy_cache (pk_context);
        if (cache == NULL)
                goto out;

        /* now validate the incoming objects */
        if (!polkit_action_validate (action))
                goto out;
        if (!polkit_caller_validate (caller))
                goto out;

        _pk_debug ("entering polkit_can_caller_do_action()");
        polkit_action_debug (action);
        polkit_caller_debug (caller);

        pfe = polkit_policy_cache_get_entry (cache, action);
        if (pfe == NULL) {
                char *action_name;
                if (!polkit_action_get_action_id (action, &action_name)) {
                        g_warning ("given action has no name");
                } else {
                        g_warning ("no action with name '%s'", action_name);
                }
                current_result = POLKIT_RESULT_UNKNOWN_ACTION;
                goto out;
        }

        polkit_policy_file_entry_debug (pfe);

        current_result = POLKIT_RESULT_UNKNOWN_ACTION;

#if 0
        /* visit modules */
        for (i = pk_context->modules; i != NULL; i = g_slist_next (i)) {
                PolKitModuleInterface *module_interface = i->data;
                PolKitModuleCanCallerDoAction func;

                func = polkit_module_get_func_can_caller_do_action (module_interface);
                if (func != NULL) {
                        PolKitModuleControl module_control;
                        PolKitResult module_result;

                        _pk_debug ("Asking module '%s'", polkit_module_get_name (module_interface));

                        module_control = polkit_module_interface_get_control (module_interface);

                        if (polkit_module_interface_check_builtin_confinement_for_caller (
                                    module_interface,
                                    pk_context,
                                    action,
                                    caller)) {
                                /* module is confined by built-in options */
                                module_result = POLKIT_RESULT_UNKNOWN_ACTION;
                                _pk_debug ("Module '%s' confined by built-in's", 
                                           polkit_module_get_name (module_interface));
                        } else {
                                module_result = func (module_interface,
                                                      pk_context,
                                                      action, 
                                                      caller);
                        }

                        /* if a module returns _UNKNOWN_ACTION, it means that it doesn't
                         * have an opinion about the query; e.g. polkit-module-allow-all(8)
                         * will return this if it's confined to only consider certain actions
                         * or certain users.
                         */
                        if (module_result != POLKIT_RESULT_UNKNOWN_ACTION) {

                                if (current_control == POLKIT_MODULE_CONTROL_ADVISE &&
                                    module_control == POLKIT_MODULE_CONTROL_ADVISE) {

                                        /* take the less strict result */
                                        if (current_result < module_result) {
                                                current_result = module_result;
                                        }

                                } else if (current_control == POLKIT_MODULE_CONTROL_ADVISE &&
                                           module_control == POLKIT_MODULE_CONTROL_MANDATORY) {
                                        
                                        /* here we just override */
                                        current_result = module_result;

                                        /* we are now in mandatory mode */
                                        current_control = POLKIT_MODULE_CONTROL_MANDATORY;
                                }
                        }
                }
        }
#endif

        /* Never return UNKNOWN_ACTION to user */
        if (current_result == POLKIT_RESULT_UNKNOWN_ACTION)
                current_result = POLKIT_RESULT_NO;
out:
        _pk_debug ("... result was %s", polkit_result_to_string_representation (current_result));
        return current_result;
}

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-context.c : context for PolicyKit
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
#include "libpolkit-context.h"
#include "libpolkit-privilege-cache.h"
#include "libpolkit-module.h"

/**
 * SECTION:libpolkit
 * @short_description: Centralized policy management.
 *
 * libpolkit is a C library for centralized policy management.
 **/

/**
 * SECTION:libpolkit-context
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
        gpointer config_changed_user_data;

        PolKitContextFileMonitorAddWatch      file_monitor_add_watch_func;
        PolKitContextFileMonitorRemoveWatch   file_monitor_remove_watch_func;

        char *priv_dir;

        PolKitPrivilegeCache *priv_cache;

        GSList *modules;
};

/**
 * libpolkit_context_new:
 * 
 * Create a new context
 * 
 * Returns: the #PolKitPrivilegeCache object
 **/
PolKitContext *
libpolkit_context_new (void)
{
        PolKitContext *pk_context;
        pk_context = g_new0 (PolKitContext, 1);
        pk_context->refcount = 1;
        return pk_context;
}

static gboolean
unload_modules (PolKitContext *pk_context)
{
        GSList *i;
        for (i = pk_context->modules; i != NULL; i = g_slist_next (i)) {
                PolKitModuleInterface *module_interface = i->data;
                libpolkit_module_interface_unref (module_interface);
        }
        g_slist_free (pk_context->modules);
        pk_context->modules = NULL;
        _pk_debug ("Unloaded modules");

        return TRUE;
}

static gboolean
load_modules (PolKitContext *pk_context, GError **error)
{
        const char *config_file;
        gboolean ret;
        char *buf;
        char *end;
        char line[256];
        char *p;
        char *q;
        gsize len;
        int line_number;
        int mod_number;

        ret = FALSE;
        buf = NULL;
        mod_number = 0;

        config_file = PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf";
        if (!g_file_get_contents (config_file,
                                  &buf,
                                  &len,
                                  error)) {
                _pk_debug ("Cannot load PolicyKit configuration file at '%s'", config_file);
                goto out;
        }

        end = buf + len;

        /* parse the config file; one line at a time (yes, this is super ugly code) */
        p = buf;
        line_number = -1;
        while (TRUE) {
                int argc;
                char **tokens;
                char *module_name;
                char *module_path;
                PolKitModuleControl module_control;
                PolKitModuleInterface *module_interface;

                line_number++;

                q = p;
                while (*q != '\n' && q != '\0' && q < end)
                        q++;
                if (*q == '\0' || q >= end) {
                        /* skip last line if it's not terminated by whitespace */
                        break;
                }
                if ((unsigned int) (q - p) > sizeof(line) - 1) {
                        _pk_debug ("Line is too long; skipping it");
                        continue;
                }
                strncpy (line, p, q - p);
                line[q - p] = '\0';
                p = q + 1;

                /* remove leading and trailing white space */
                g_strstrip (line);

                /* comments, blank lines are fine; just skip them */
                if (line[0] == '#' || strlen (line) == 0) {
                        continue;
                }

                /*_pk_debug ("Looking at line: '%s'", line);*/

                if (!g_shell_parse_argv (line, &argc, &tokens, NULL)) {
                        _pk_debug ("Cannot parse line %d - skipping", line_number);
                        continue;
                }
                if (argc < 2) {
                        _pk_debug ("Line %d is malformed - skipping line", line_number);
                        g_strfreev (tokens);
                        continue;
                }
                if (!libpolkit_module_control_from_string_representation (tokens[0], &module_control)) {
                        _pk_debug ("Unknown module_control '%s' at line %d - skipping line", tokens[0], line_number);
                        g_strfreev (tokens);
                        continue;
                }
                module_name = tokens[1];

                module_path = g_strdup_printf (PACKAGE_LIB_DIR "/PolicyKit/modules/%s", module_name);
                _pk_debug ("MODULE: number=%d control=%d name=%s argc=%d", 
                           mod_number, module_control, module_name, argc - 1);
                module_interface = libpolkit_module_interface_load_module (module_path, 
                                                                           module_control, 
                                                                           argc - 1, 
                                                                           tokens + 1);
                g_free (module_path);

                if (module_interface != NULL) {
                        pk_context->modules = g_slist_append (pk_context->modules, module_interface);
                        mod_number++;
                }
                g_strfreev (tokens);

        }

        ret = TRUE;

out:
        if (buf != NULL)
                g_free (buf);

        _pk_debug ("Loaded %d modules in total", mod_number);
        return ret;
}

static void
_config_file_events (PolKitContext                 *pk_context,
                     PolKitContextFileMonitorEvent  event_mask,
                     const char                    *path,
                     gpointer                       user_data)
{
        _pk_debug ("Config file changed");
        unload_modules (pk_context);
        load_modules (pk_context, NULL);

        /* signal that our configuration (may have) changed */
        if (pk_context->config_changed_cb) {
                pk_context->config_changed_cb (pk_context, pk_context->config_changed_user_data);
        }
}

static void
_privilege_dir_events (PolKitContext                 *pk_context,
                       PolKitContextFileMonitorEvent  event_mask,
                       const char                    *path,
                       gpointer                       user_data)
{
        /* mark cache of privilege files as stale.. (will be populated on-demand, see _get_cache()) */
        if (pk_context->priv_cache != NULL) {
                _pk_debug ("Something happened in %s - invalidating cache", pk_context->priv_dir);
                libpolkit_privilege_cache_unref (pk_context->priv_cache);
                pk_context->priv_cache = NULL;
        }

        /* signal that our configuration (may have) changed */
        if (pk_context->config_changed_cb) {
                pk_context->config_changed_cb (pk_context, pk_context->config_changed_user_data);
        }
}

/**
 * libpolkit_context_init:
 * @pk_context: the context object
 * @error: return location for error
 * 
 * Initializes a new context; loads PolicyKit files from
 * /etc/PolicyKit/privileges unless the environment variable
 * $POLKIT_PRIVILEGE_DIR points to a location.
 *
 * Returns: #FALSE if @error was set, otherwise #TRUE
 **/
gboolean
libpolkit_context_init (PolKitContext *pk_context, GError **error)
{
        const char *dirname;

        dirname = getenv ("POLKIT_PRIVILEGE_DIR");
        if (dirname != NULL) {
                pk_context->priv_dir = g_strdup (dirname);
        } else {
                pk_context->priv_dir = g_strdup (PACKAGE_SYSCONF_DIR "/PolicyKit/privileges");
        }
        _pk_debug ("Using privilege files from directory %s", pk_context->priv_dir);

        /* Load modules */
        if (!load_modules (pk_context, error))
                goto error;

        /* don't populate the cache until it's needed.. */

        if (pk_context->file_monitor_add_watch_func == NULL) {
                _pk_debug ("No file monitor; cannot monitor '%s' for .priv file changes", dirname);
        } else {
                /* Watch when privilege definitions file change */
                pk_context->file_monitor_add_watch_func (pk_context, 
                                                         pk_context->priv_dir,
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_CREATE|
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_DELETE|
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_CHANGE,
                                                         _privilege_dir_events,
                                                         NULL);

                /* Config file changes */
                pk_context->file_monitor_add_watch_func (pk_context, 
                                                         PACKAGE_SYSCONF_DIR "/PolicyKit",
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_CREATE|
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_DELETE|
                                                         POLKIT_CONTEXT_FILE_MONITOR_EVENT_CHANGE,
                                                         _config_file_events,
                                                         NULL);
        }

        return TRUE;
error:
        if (pk_context != NULL)
                libpolkit_context_unref (pk_context);

        return FALSE;
}

/**
 * libpolkit_context_ref:
 * @pk_context: the context object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitContext *
libpolkit_context_ref (PolKitContext *pk_context)
{
        g_return_val_if_fail (pk_context != NULL, pk_context);
        pk_context->refcount++;
        return pk_context;
}

/**
 * libpolkit_context_unref:
 * @pk_context: the context object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_context_unref (PolKitContext *pk_context)
{

        g_return_if_fail (pk_context != NULL);
        pk_context->refcount--;
        if (pk_context->refcount > 0) 
                return;

        unload_modules (pk_context);

        g_free (pk_context);
}

/**
 * libpolkit_context_set_config_changed:
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
 **/
void
libpolkit_context_set_config_changed (PolKitContext                *pk_context, 
                                      PolKitContextConfigChangedCB cb, 
                                      gpointer                     user_data)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->config_changed_cb = cb;
        pk_context->config_changed_user_data = user_data;
}

/**
 * libpolkit_context_set_file_monitor:
 * @pk_context: the context object
 * @add_watch_func: the function that the PolicyKit library can invoke to start watching a file
 * @remove_watch_func: the function that the PolicyKit library can invoke to stop watching a file
 * 
 * Register a functions that PolicyKit can use for watching files.
 **/
void
libpolkit_context_set_file_monitor (PolKitContext                        *pk_context, 
                                    PolKitContextFileMonitorAddWatch      add_watch_func,
                                    PolKitContextFileMonitorRemoveWatch   remove_watch_func)
{
        g_return_if_fail (pk_context != NULL);
        pk_context->file_monitor_add_watch_func = add_watch_func;
        pk_context->file_monitor_remove_watch_func = remove_watch_func;
}


/**
 * libpolkit_context_get_privilege_cache:
 * @pk_context: the context
 * 
 * Get the #PolKitPrivilegeCache object that holds all the defined privileges as well as their defaults.
 * 
 * Returns: the #PolKitPrivilegeCache object. Caller shall not unref it.
 **/
PolKitPrivilegeCache *
libpolkit_context_get_privilege_cache (PolKitContext *pk_context)
{
        g_return_val_if_fail (pk_context != NULL, NULL);

        if (pk_context->priv_cache == NULL) {
                GError *error;

                _pk_debug ("Populating cache from directory %s", pk_context->priv_dir);

                error = NULL;
                pk_context->priv_cache = libpolkit_privilege_cache_new (pk_context->priv_dir, &error);
                if (pk_context->priv_cache == NULL) {
                        g_warning ("Error loading privilege files from %s: %s", 
                                   pk_context->priv_dir, error->message);
                        g_error_free (error);
                } else {
                        /*libpolkit_privilege_cache_debug (pk_context->priv_cache)*/;
                }
        }

        return pk_context->priv_cache;
}


/**
 * libpolkit_context_get_seat_resource_association:
 * @pk_context: the PolicyKit context
 * @visitor: visitor function
 * @user_data: user data
 *
 * Retrieve information about what resources are associated to what
 * seats. Note that a resource may be associated to more than one
 * seat. This information stems from user configuration and consumers
 * of this information that know better (e.g. HAL) may choose to
 * override it. 
 *
 * Typically, this information is used to e.g. bootstrap the system
 * insofar that it can be used to start login greeters on the given
 * video hardware (e.g. resources) on the given user-configured seats.
 *
 * If a resource is not associated with any seat, it is assumed to be
 * available to any local seat.
 *
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW or
 * #LIBPOLKIT_RESULT_YES (if the callback was invoked)
 */
PolKitResult
libpolkit_context_get_seat_resource_association (PolKitContext       *pk_context,
                                                 PolKitSeatVisitorCB  visitor,
                                                 gpointer            *user_data)
{
        return LIBPOLKIT_RESULT_YES;
}

/**
 * libpolkit_context_is_resource_associated_with_seat:
 * @pk_context: the PolicyKit context
 * @resource: the resource in question
 * @seat: the seat
 *
 * Determine if a given resource is associated with a given seat. The
 * same comments noted in libpolkit_get_seat_resource_association() about the
 * source purely being user configuration applies here as well.
 *
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
 * #LIBPOLKIT_RESULT_YES, #LIBPOLKIT_RESULT_NO.
 */
PolKitResult
libpolkit_context_is_resource_associated_with_seat (PolKitContext   *pk_context,
                                                    PolKitResource  *resource,
                                                    PolKitSeat      *seat)
{
        return LIBPOLKIT_RESULT_NO;
}

/**
 * libpolkit_context_can_session_access_resource:
 * @pk_context: the PolicyKit context
 * @privilege: the type of access to check for
 * @resource: the resource in question
 * @session: the session in question
 *
 * Determine if a given session can access a given resource in a given way.
 *
 * Returns: A #PolKitResult - can only be one of
 * #LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
 * #LIBPOLKIT_RESULT_YES, #LIBPOLKIT_RESULT_NO.
 */
PolKitResult
libpolkit_context_can_session_access_resource (PolKitContext   *pk_context,
                                               PolKitPrivilege *privilege,
                                               PolKitResource  *resource,
                                               PolKitSession   *session)
{
        PolKitPrivilegeCache *cache;
        PolKitPrivilegeFileEntry *pfe;
        PolKitResult current_result;
        PolKitModuleControl current_control;
        GSList *i;

        current_result = LIBPOLKIT_RESULT_NO;

        cache = libpolkit_context_get_privilege_cache (pk_context);
        if (cache == NULL)
                goto out;

        _pk_debug ("entering libpolkit_can_session_access_resource()");
        libpolkit_privilege_debug (privilege);
        libpolkit_resource_debug (resource);
        libpolkit_session_debug (session);

        pfe = libpolkit_privilege_cache_get_entry (cache, privilege);
        if (pfe == NULL) {
                char *privilege_name;
                if (!libpolkit_privilege_get_privilege_id (privilege, &privilege_name)) {
                        g_warning ("given privilege has no name");
                } else {
                        g_warning ("no privilege with name '%s'", privilege_name);
                }
                current_result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
                goto out;
        }

        libpolkit_privilege_file_entry_debug (pfe);

        current_result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
        current_control = LIBPOLKIT_MODULE_CONTROL_ADVISE; /* start with advise */

        /* visit modules */
        for (i = pk_context->modules; i != NULL; i = g_slist_next (i)) {
                PolKitModuleInterface *module_interface = i->data;
                PolKitModuleCanSessionAccessResource func;

                func = libpolkit_module_get_func_can_session_access_resource (module_interface);
                if (func != NULL) {
                        PolKitModuleControl module_control;
                        PolKitResult module_result;

                        _pk_debug ("Asking module '%s'", libpolkit_module_get_name (module_interface));

                        module_control = libpolkit_module_interface_get_control (module_interface);

                        if (libpolkit_module_interface_check_builtin_confinement_for_session (
                                    module_interface,
                                    pk_context,
                                    privilege,
                                    resource,
                                    session)) {
                                /* module is confined by built-in options */
                                module_result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
                                _pk_debug ("Module '%s' confined by built-in's", 
                                           libpolkit_module_get_name (module_interface));
                        } else {
                                module_result = func (module_interface,
                                                      pk_context,
                                                      privilege, 
                                                      resource, 
                                                      session);
                        }

                        /* if a module returns _UNKNOWN_PRIVILEGE, it means that it doesn't
                         * have an opinion about the query; e.g. polkit-module-allow-all(8)
                         * will return this if it's confined to only consider certain privileges
                         * or certain users.
                         */
                        if (module_result != LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE) {

                                if (current_control == LIBPOLKIT_MODULE_CONTROL_ADVISE &&
                                    module_control == LIBPOLKIT_MODULE_CONTROL_ADVISE) {

                                        /* take the less strict result */
                                        if (current_result < module_result) {
                                                current_result = module_result;
                                        }

                                } else if (current_control == LIBPOLKIT_MODULE_CONTROL_ADVISE &&
                                           module_control == LIBPOLKIT_MODULE_CONTROL_MANDATORY) {
                                        
                                        /* here we just override */
                                        current_result = module_result;

                                        /* we are now in mandatory mode */
                                        current_control = LIBPOLKIT_MODULE_CONTROL_MANDATORY;
                                }
                        }
                }
        }

        /* Never return UNKNOWN_PRIVILEGE to user */
        if (current_result == LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE)
                current_result = LIBPOLKIT_RESULT_NO;

out:
        _pk_debug ("... result was %s", libpolkit_result_to_string_representation (current_result));
        return current_result;
}

/**
 * libpolkit_context_can_caller_access_resource:
 * @pk_context: the PolicyKit context
 * @privilege: the type of access to check for
 * @resource: the resource in question
 * @caller: the resource in question
 *
 * Determine if a given caller can access a given resource in a given way.
 *
 * Returns: A #PolKitResult specifying if, and how, the caller can
 * access the resource in the given way
 */
PolKitResult
libpolkit_context_can_caller_access_resource (PolKitContext   *pk_context,
                                              PolKitPrivilege *privilege,
                                              PolKitResource  *resource,
                                              PolKitCaller    *caller)
{
        PolKitPrivilegeCache *cache;
        PolKitPrivilegeFileEntry *pfe;
        PolKitResult current_result;
        PolKitModuleControl current_control;
        GSList *i;

        current_result = LIBPOLKIT_RESULT_NO;

        cache = libpolkit_context_get_privilege_cache (pk_context);
        if (cache == NULL)
                goto out;

        _pk_debug ("entering libpolkit_can_caller_access_resource()");
        libpolkit_privilege_debug (privilege);
        libpolkit_resource_debug (resource);
        libpolkit_caller_debug (caller);

        pfe = libpolkit_privilege_cache_get_entry (cache, privilege);
        if (pfe == NULL) {
                char *privilege_name;
                if (!libpolkit_privilege_get_privilege_id (privilege, &privilege_name)) {
                        g_warning ("given privilege has no name");
                } else {
                        g_warning ("no privilege with name '%s'", privilege_name);
                }
                current_result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
                goto out;
        }

        libpolkit_privilege_file_entry_debug (pfe);

        current_result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
        current_control = LIBPOLKIT_MODULE_CONTROL_ADVISE; /* start with advise */

        /* visit modules */
        for (i = pk_context->modules; i != NULL; i = g_slist_next (i)) {
                PolKitModuleInterface *module_interface = i->data;
                PolKitModuleCanCallerAccessResource func;

                func = libpolkit_module_get_func_can_caller_access_resource (module_interface);
                if (func != NULL) {
                        PolKitModuleControl module_control;
                        PolKitResult module_result;

                        _pk_debug ("Asking module '%s'", libpolkit_module_get_name (module_interface));

                        module_control = libpolkit_module_interface_get_control (module_interface);

                        if (libpolkit_module_interface_check_builtin_confinement_for_caller (
                                    module_interface,
                                    pk_context,
                                    privilege,
                                    resource,
                                    caller)) {
                                /* module is confined by built-in options */
                                module_result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
                                _pk_debug ("Module '%s' confined by built-in's", 
                                           libpolkit_module_get_name (module_interface));
                        } else {
                                module_result = func (module_interface,
                                                      pk_context,
                                                      privilege, 
                                                      resource, 
                                                      caller);
                        }

                        /* if a module returns _UNKNOWN_PRIVILEGE, it means that it doesn't
                         * have an opinion about the query; e.g. polkit-module-allow-all(8)
                         * will return this if it's confined to only consider certain privileges
                         * or certain users.
                         */
                        if (module_result != LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE) {

                                if (current_control == LIBPOLKIT_MODULE_CONTROL_ADVISE &&
                                    module_control == LIBPOLKIT_MODULE_CONTROL_ADVISE) {

                                        /* take the less strict result */
                                        if (current_result < module_result) {
                                                current_result = module_result;
                                        }

                                } else if (current_control == LIBPOLKIT_MODULE_CONTROL_ADVISE &&
                                           module_control == LIBPOLKIT_MODULE_CONTROL_MANDATORY) {
                                        
                                        /* here we just override */
                                        current_result = module_result;

                                        /* we are now in mandatory mode */
                                        current_control = LIBPOLKIT_MODULE_CONTROL_MANDATORY;
                                }
                        }
                }
        }

        /* Never return UNKNOWN_PRIVILEGE to user */
        if (current_result == LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE)
                current_result = LIBPOLKIT_RESULT_NO;
out:
        _pk_debug ("... result was %s", libpolkit_result_to_string_representation (current_result));
        return current_result;
}

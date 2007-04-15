/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-module.c : PolicyKit loadable module interface
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

/**
 * SECTION:libpolkit-module
 * @short_description: PolicyKit loadable module interface
 *
 * These functions are used by loadable PolicyKit modules.
 **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include <dlfcn.h>
#include <regex.h>
#include <pwd.h>
#include <grp.h>
#include <glib.h>
#include <unistd.h>

#include "libpolkit-debug.h"
#include "libpolkit-module.h"

/**
 * PolKitModuleInterface:
 *
 * Objects of this class are used to interface with PolicyKit modules
 **/
struct PolKitModuleInterface
{
        int refcount;
        void *dlopen_handle;
        char *name;

        void *module_user_data;
        PolKitModuleControl module_control;

        PolKitModuleInitialize                     func_initialize;
        PolKitModuleShutdown                       func_shutdown;
        PolKitModuleGetSeatResourceAssociation     func_get_seat_resource_association;
        PolKitModuleIsResourceAssociatedWithSeat   func_is_resource_associated_with_seat;
        PolKitModuleCanSessionAccessResource       func_can_session_access_resource;
        PolKitModuleCanCallerAccessResource        func_can_caller_access_resource;

        polkit_bool_t builtin_have_action_regex;
        regex_t  builtin_action_regex_compiled;

        GSList *builtin_users;
};

static uid_t
_util_name_to_uid (const char *username, gid_t *default_gid)
{
        int rc;
        uid_t res;
        char *buf = NULL;
        unsigned int bufsize;
        struct passwd pwd;
        struct passwd *pwdp;

        res = (uid_t) -1;

        bufsize = sysconf (_SC_GETPW_R_SIZE_MAX);
        buf = g_new0 (char, bufsize);
                
        rc = getpwnam_r (username, &pwd, buf, bufsize, &pwdp);
        if (rc != 0 || pwdp == NULL) {
                /*g_warning ("getpwnam_r() returned %d", rc);*/
                goto out;
        }

        res = pwdp->pw_uid;
        if (default_gid != NULL)
                *default_gid = pwdp->pw_gid;

out:
        g_free (buf);
        return res;
}

static void
_parse_builtin_remove_option (int *argc, char *argv[], int position)
{
        int n;
        for (n = position; n < *argc; n++)
                argv[n] = argv[n+1];
        (*argc)--;
}

static polkit_bool_t
_parse_builtin (PolKitModuleInterface *mi, int *argc, char *argv[])
{
        int n;
        polkit_bool_t ret;

        ret = FALSE;

        for (n = 1; n < *argc; ) {
                if (g_str_has_prefix (argv[n], "action=")) {
                        const char *regex;

                        if (mi->builtin_have_action_regex) {
                                _pk_debug ("Already have option 'action='");
                                goto error;
                        }

                        regex = argv[n] + 10;
                        if (regcomp (&(mi->builtin_action_regex_compiled), regex, REG_EXTENDED) != 0) {
                                _pk_debug ("Regex '%s' didn't compile", regex);
                                goto error;
                        }
                        mi->builtin_have_action_regex = TRUE;

                        _pk_debug ("Compiled regex '%s' for option 'action=' OK", regex);

                        _parse_builtin_remove_option (argc, argv, n);
                } else if (g_str_has_prefix (argv[n], "user=")) {
                        const char *user;
                        uid_t uid;
                        GSList *i;

                        user = argv[n] + 5;
                        uid = _util_name_to_uid (user, NULL);
                        if ((int) uid == -1) {
                                _pk_debug ("Unknown user name '%s'", user);
                                goto error;
                        }

                        for (i = mi->builtin_users; i != NULL; i = g_slist_next (i)) {
                                uid_t uid_in_list = GPOINTER_TO_INT (i->data);
                                if (uid_in_list == uid) {
                                        _pk_debug ("Already have user '%s'", user);
                                        goto error;
                                }
                        }                        

                        _pk_debug ("adding uid %d", uid);
                        mi->builtin_users = g_slist_prepend (mi->builtin_users, GINT_TO_POINTER (uid));

                        _parse_builtin_remove_option (argc, argv, n);
                } else {
                        n++;
                }
        }

        ret = TRUE;

error:
        return ret;
}

/**
 * libpolkit_module_interface_load_module:
 * @name: name of module, e.g. "polkit-module-default.so"
 * @module_control: the module control; from the configuration file
 * @argc: number arguments to pass
 * @argv: argument vector, the first argument must be the filename/path to the module
 * 
 * Load and initialize a PolicyKit module
 * 
 * Returns: A #PolKitModuleInterface object on success; #NULL on failure.
 **/
PolKitModuleInterface *
libpolkit_module_interface_load_module (const char *name, PolKitModuleControl module_control, int argc, char *argv[])
{
        void *handle;
        PolKitModuleInterface *mi;
        polkit_bool_t (*func) (PolKitModuleInterface *);

        mi = NULL;

        _pk_debug ("loading %s", name);

        handle = dlopen (name, RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
                _pk_debug ("Cannot load module '%s'", name);
                goto error;
        }

        func = dlsym (handle, "libpolkit_module_set_functions");
        if (func == NULL) {
                _pk_debug ("Cannot get symbol 'libpolkit_module_set_functions' in module '%s'", name);
                goto error;
        }

        _pk_debug ("func = %p", func);

        mi = libpolkit_module_interface_new ();
        if (!func (mi)) {
                _pk_debug ("Module '%s' returned FALSE when asked to set functions", name);
                goto error;
        }

        if (mi->func_initialize == NULL) {
                _pk_debug ("Module '%s' didn't set initialize function", name);
                goto error;
        }
        
        if (mi->func_shutdown == NULL) {
                _pk_debug ("Module '%s' didn't set shutdown function", name);
                goto error;
        }

        if (!_parse_builtin (mi, &argc, argv)) {
                _pk_debug ("Error parsing built-in module options for '%s'", name);
                goto error;
        }

        if (!mi->func_initialize (mi, argc, argv)) {
                _pk_debug ("Module '%s' returned FALSE in initialization function", name);
                goto error;
        }

        mi->dlopen_handle = handle;
        mi->name = g_strdup (name);
        mi->module_control = module_control;
        return mi;
error:
        if (mi != NULL)
                libpolkit_module_interface_unref (mi);
        if (handle != NULL)
                dlclose (handle);
        return NULL;
}

/**
 * libpolkit_module_get_name:
 * @module_interface: the module interface
 * 
 * Get the name of the module
 * 
 * Returns: name or #NULL if an error occured
 **/
const char *
libpolkit_module_get_name (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->name;
}


/**
 * libpolkit_module_interface_new:
 * 
 * Create a new #PolKitModuleInterface object.
 * 
 * Returns: the new object
 **/
PolKitModuleInterface *
libpolkit_module_interface_new (void)
{
        PolKitModuleInterface *module_interface;
        module_interface = g_new0 (PolKitModuleInterface, 1);
        module_interface->refcount = 1;
        return module_interface;
}

/**
 * libpolkit_module_interface_ref:
 * @module_interface: the module_interface object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitModuleInterface *
libpolkit_module_interface_ref (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, module_interface);
        module_interface->refcount++;
        return module_interface;
}

/**
 * libpolkit_module_interface_unref:
 * @module_interface: the module_interface object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
libpolkit_module_interface_unref (PolKitModuleInterface *module_interface)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->refcount--;
        if (module_interface->refcount > 0) 
                return;

        /* builtins */
        if (module_interface->builtin_have_action_regex)
                regfree (&module_interface->builtin_action_regex_compiled);
        g_slist_free (module_interface->builtin_users);

        /* shutdown the module and unload it */
        if (module_interface->func_shutdown != NULL)
                module_interface->func_shutdown (module_interface);
        if (module_interface->dlopen_handle != NULL)
                dlclose (module_interface->dlopen_handle);

        g_free (module_interface->name);
        g_free (module_interface);
}

/**
 * libpolkit_module_set_func_initialize:
 * @module_interface: the module interface
 * @func: the function pointer
 * 
 * Set the function pointer.
 **/
void
libpolkit_module_set_func_initialize (PolKitModuleInterface  *module_interface, 
                                      PolKitModuleInitialize  func)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->func_initialize = func;
}

/**
 * libpolkit_module_set_func_shutdown:
 * @module_interface: the module interface 
 * @func: the function pointer
 * 
 * Set the function pointer.
 **/
void 
libpolkit_module_set_func_shutdown (PolKitModuleInterface *module_interface, 
                                    PolKitModuleShutdown   func)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->func_shutdown = func;
}

/**
 * libpolkit_module_set_func_get_seat_resource_association:
 * @module_interface: the module interface 
 * @func: the function pointer
 * 
 * Set the function pointer.
 **/
void 
libpolkit_module_set_func_get_seat_resource_association (PolKitModuleInterface                   *module_interface,
                                                         PolKitModuleGetSeatResourceAssociation  func)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->func_get_seat_resource_association = func;
}

/**
 * libpolkit_module_set_func_is_resource_associated_with_seat:
 * @module_interface: the module interface 
 * @func: the function pointer
 * 
 * Set the function pointer.
 **/
void libpolkit_module_set_func_is_resource_associated_with_seat (PolKitModuleInterface               *module_interface,
                                                                 PolKitModuleIsResourceAssociatedWithSeat func)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->func_is_resource_associated_with_seat = func;
}

/**
 * libpolkit_module_set_func_can_session_access_resource:
 * @module_interface: the module interface 
 * @func: the function pointer
 * 
 * Set the function pointer.
 **/
void libpolkit_module_set_func_can_session_access_resource (PolKitModuleInterface                *module_interface,
                                                            PolKitModuleCanSessionAccessResource  func)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->func_can_session_access_resource = func;
}

/**
 * libpolkit_module_set_func_can_caller_access_resource:
 * @module_interface: the module interface 
 * @func: the function pointer
 * 
 * Set the function pointer.
 **/
void libpolkit_module_set_func_can_caller_access_resource (PolKitModuleInterface               *module_interface,
                                                           PolKitModuleCanCallerAccessResource  func)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->func_can_caller_access_resource = func;
}

/**
 * libpolkit_module_get_func_initialize:
 * @module_interface: the module interface 
 * 
 * Get the function pointer.
 * 
 * Returns: Function pointer or #NULL if it's unavailable or an error occured 
 **/
PolKitModuleInitialize 
libpolkit_module_get_func_initialize (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->func_initialize;
}

/**
 * libpolkit_module_get_func_shutdown:
 * @module_interface: the module interface 
 * 
 * Get the function pointer.
 * 
 * Returns: Function pointer or #NULL if it's unavailable or an error occured 
 **/
PolKitModuleShutdown
libpolkit_module_get_func_shutdown (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->func_shutdown;
}

/**
 * libpolkit_module_get_func_get_seat_resource_association:
 * @module_interface: the module interface 
 * 
 * Get the function pointer.
 * 
 * Returns: Function pointer or #NULL if it's unavailable or an error occured 
 **/
PolKitModuleGetSeatResourceAssociation
libpolkit_module_get_func_get_seat_resource_association (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->func_get_seat_resource_association;
}

/**
 * libpolkit_module_get_func_is_resource_associated_with_seat:
 * @module_interface: the module interface 
 * 
 * Get the function pointer.
 * 
 * Returns: Function pointer or #NULL if it's unavailable or an error occured 
 **/
PolKitModuleIsResourceAssociatedWithSeat
libpolkit_module_get_func_is_resource_associated_with_seat (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->func_is_resource_associated_with_seat;
}

/**
 * libpolkit_module_get_func_can_session_access_resource:
 * @module_interface: the module interface 
 * 
 * Get the function pointer.
 * 
 * Returns: Function pointer or #NULL if it's unavailable or an error occured 
 **/
PolKitModuleCanSessionAccessResource
libpolkit_module_get_func_can_session_access_resource (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->func_can_session_access_resource;
}

/**
 * libpolkit_module_get_func_can_caller_access_resource:
 * @module_interface: the module interface 
 * 
 * Get the function pointer.
 * 
 * Returns: Function pointer or #NULL if it's unavailable or an error occured
 **/
PolKitModuleCanCallerAccessResource
libpolkit_module_get_func_can_caller_access_resource (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->func_can_caller_access_resource;
}


/**
 * libpolkit_module_interface_get_control:
 * @module_interface: the module interface
 * 
 * Get the control for this module.
 * 
 * Returns: A #PolKitModuleControl value.
 **/
PolKitModuleControl 
libpolkit_module_interface_get_control (PolKitModuleInterface *module_interface)
{
        /* hmm, should we have UNKNOWN? */
        g_return_val_if_fail (module_interface != NULL, LIBPOLKIT_MODULE_CONTROL_MANDATORY);
        return module_interface->module_control;
}

static const struct {
        PolKitModuleControl module_control;
        const char *str;
} mapping[] = 
{
        {LIBPOLKIT_MODULE_CONTROL_ADVISE, "advise"},
        {LIBPOLKIT_MODULE_CONTROL_MANDATORY, "mandatory"},
        {0, NULL}
};

/**
 * libpolkit_module_control_to_string_representation:
 * @module_control: the given value
 * 
 * Gives a textual representation of a #PolKitModuleControl object.
 * 
 * Returns: The textual representation or #NULL if the value passed is invalid
 **/
const char *
libpolkit_module_control_to_string_representation (PolKitModuleControl module_control)
{
        if (module_control < 0 || module_control >= LIBPOLKIT_MODULE_CONTROL_N_CONTROLS) {
                g_warning ("The passed module control identifier, %d, is not valid", module_control);
                return NULL;
        }

        return mapping[module_control].str;
}

/**
 * libpolkit_module_control_from_string_representation:
 * @string: the textual representation
 * @out_module_control: return location for the value
 * 
 * Given a textual representation of a #PolKitModuleControl object, find the #PolKitModuleControl value.
 * 
 * Returns: TRUE if the textual representation was valid, otherwise FALSE
 **/
polkit_bool_t
libpolkit_module_control_from_string_representation (const char *string, PolKitModuleControl *out_module_control)
{
        int n;

        g_return_val_if_fail (out_module_control != NULL, FALSE);

        for (n = 0; n < LIBPOLKIT_MODULE_CONTROL_N_CONTROLS; n++) {
                if (mapping[n].str == NULL)
                        break;
                if (g_ascii_strcasecmp (mapping[n].str, string) == 0) {
                        *out_module_control = mapping[n].module_control;
                        goto found;
                }
        }

        return FALSE;
found:
        return TRUE;
}


/**
 * libpolkit_module_set_user_data:
 * @module_interface: module interface
 * @user_data: user data to set
 * 
 * Set user data. A PolicyKit module should use these instead of
 * global variables as multiple instances of the module may be
 * instantiated at the same time.
 **/
void
libpolkit_module_set_user_data (PolKitModuleInterface *module_interface, void *user_data)
{
        g_return_if_fail (module_interface != NULL);
        module_interface->module_user_data = user_data;
}

/**
 * libpolkit_module_get_user_data:
 * @module_interface: module interface
 * 
 * Get user data.
 * 
 * Returns: The user data set with libpolkit_module_set_user_data()
 **/
void *
libpolkit_module_get_user_data   (PolKitModuleInterface *module_interface)
{
        g_return_val_if_fail (module_interface != NULL, NULL);
        return module_interface->module_user_data;
}

static polkit_bool_t 
_check_action (PolKitModuleInterface *module_interface, PolKitAction *action)
{
        polkit_bool_t ret;

        ret = FALSE;

        if (module_interface->builtin_have_action_regex) {
                char *action_name;
                if (libpolkit_action_get_action_id (action, &action_name)) {
                        if (regexec (&module_interface->builtin_action_regex_compiled, 
                                     action_name, 0, NULL, 0) == 0) {
                                ret = TRUE;
                        }
                }
        } else {
                ret = TRUE;
        }

        return ret;
}

/*----*/

static polkit_bool_t
_check_uid_in_list (GSList *list, uid_t given_uid)
{
        GSList *i;

        for (i = list; i != NULL; i = g_slist_next (i)) {
                uid_t uid = GPOINTER_TO_INT (i->data);
                if (given_uid == uid)
                        return TRUE;                
        }
        return FALSE;
}

static polkit_bool_t
_check_users_for_session (PolKitModuleInterface *module_interface, PolKitSession *session)
{
        uid_t uid;
        GSList *list;
        if ((list = module_interface->builtin_users) == NULL)
                return TRUE;
        if (session == NULL)
                return FALSE;
        if (!libpolkit_session_get_uid (session, &uid))
                return FALSE;
        return _check_uid_in_list (list, uid);
}

static polkit_bool_t
_check_users_for_caller (PolKitModuleInterface *module_interface, PolKitCaller *caller)
{
        uid_t uid;
        GSList *list;
        if ((list = module_interface->builtin_users) == NULL)
                return TRUE;
        if (caller == NULL)
                return FALSE;
        if (!libpolkit_caller_get_uid (caller, &uid))
                return FALSE;
        return _check_uid_in_list (list, uid);
}


/**
 * libpolkit_module_interface_check_builtin_confinement_for_session:
 * @module_interface: the given module
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @resource: the resource in question
 * @session: the session in question
 * 
 * Check whether some of the built-in module options (e.g. action="hal-storage-*", 
 * user=davidz) confines the given module, e.g. whether it should be skipped.
 * 
 * Returns: TRUE if, and only if, the module is confined from handling the request
 **/
polkit_bool_t
libpolkit_module_interface_check_builtin_confinement_for_session (PolKitModuleInterface *module_interface,
                                                                  PolKitContext   *pk_context,
                                                                  PolKitAction *action,
                                                                  PolKitResource  *resource,
                                                                  PolKitSession   *session)
{
        polkit_bool_t ret;
        ret = TRUE;

        g_return_val_if_fail (module_interface != NULL, ret);

        if (!_check_action (module_interface, action))
                goto out;
        if (!_check_users_for_session (module_interface, session))
                goto out;

        /* not confined */
        ret = FALSE;
out:
        return ret;
}

/**
 * libpolkit_module_interface_check_builtin_confinement_for_caller:
 * @module_interface: the given module
 * @pk_context: the PolicyKit context
 * @action: the type of access to check for
 * @resource: the resource in question
 * @caller: the resource in question
 * 
 * Check whether some of the built-in module options (e.g. action="hal-storage-*", 
 * user=davidz) confines the given module, e.g. whether it should be skipped.
 * 
 * Returns: TRUE if, and only if, the module is confined from handling the request
 **/
polkit_bool_t
libpolkit_module_interface_check_builtin_confinement_for_caller (PolKitModuleInterface *module_interface,
                                                                 PolKitContext   *pk_context,
                                                                 PolKitAction *action,
                                                                 PolKitResource  *resource,
                                                                 PolKitCaller    *caller)
{
        polkit_bool_t ret;
        ret = TRUE;

        g_return_val_if_fail (module_interface != NULL, ret);

        if (!_check_action (module_interface, action))
                goto out;
        if (!_check_users_for_caller (module_interface, caller))
                goto out;

        /* not confined */
        ret = FALSE;
out:
        return ret;
}

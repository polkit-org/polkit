/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-module-grant.c : determine policy by looking at grants
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <polkit/polkit.h>
#include <glib.h>

/* The symbol that polkit looks up when loading this module */
polkit_bool_t polkit_module_set_functions (PolKitModuleInterface *module_interface);

static polkit_bool_t
_module_init (PolKitModuleInterface *module_interface, int argc, char *argv[])
{
        return TRUE;
}

static void
_module_shutdown (PolKitModuleInterface *module_interface)
{
}



static PolKitResult
_module_can_session_access_resource (PolKitModuleInterface *module_interface,
                                     PolKitContext         *pk_context,
                                     PolKitAction          *action,
                                     PolKitResource        *resource,
                                     PolKitSession         *session)
{
        return POLKIT_RESULT_UNKNOWN_ACTION;
}

static PolKitResult
_module_can_caller_access_resource (PolKitModuleInterface *module_interface,
                                    PolKitContext         *pk_context,
                                    PolKitAction          *action,
                                    PolKitResource        *resource,
                                    PolKitCaller          *caller)
{
        char *grant_file;
        PolKitSession *session;
        PolKitResult result;

        result = POLKIT_RESULT_UNKNOWN_ACTION;

        /* file format:
         *
         * file: /var/[lib,run]/PolicyKit/grant/<action-name>.grant
         *
         * contents:
         *    <uid1>[ <session-objpath>]\n          # only makes sense for run
         *    <uid2>\n
         *    ...
         *
         * - run is used for temporarily granted privileges
         * - lib is used for permanently granted privileges
         *
         * FHS guarantees that the files /var/run/PolicyKit are
         * deleted upon reboots so we just need to ensure that
         * ConsoleKit session id's are unique per system (TODO: Ask Jon
         * to make ConsoleKit guarantee this).
         */

        uid_t invoking_user_id;
        char *action_name;
        char *session_objpath;
        const char *session_name;
        char *resource_type;
        char *resource_id;
        char *resource_str_to_hash;
        char *dbus_name;
        guint resource_hash;

        if (!polkit_action_get_action_id (action, &action_name))
                goto out;
        if (!polkit_caller_get_uid (caller, &invoking_user_id))
                goto out;

        if (resource == NULL)
                goto out;
        if (!polkit_resource_get_resource_type (resource, &resource_type))
                goto out;
        if (!polkit_resource_get_resource_id (resource, &resource_id))
                goto out;

        session_name = NULL;
        if (!polkit_caller_get_ck_session (caller, &session))
                goto out;
        if (!polkit_caller_get_dbus_name (caller, &dbus_name))
                goto out;
        if (!polkit_session_get_ck_objref (session, &session_objpath))
                goto out;

        session_name = g_basename (session_objpath);
        resource_str_to_hash = g_strdup_printf ("%s:%s", resource_type, resource_id);
        resource_hash = g_str_hash (resource_str_to_hash);
        g_free (resource_str_to_hash);

        /* TODO: FIXME: XXX: this format of storing granted privileges needs be redone
         *
         * this concerns these two files
         * - polkit-grant/polkit-grant-helper.c
         * - modules/grant/polkit-module-grant.c
         */

        /*
         * /var/lib/PolicyKit/uid_<uid>_<action>_<resource-hash>.grant
         *                    uid_<uid>_<action>.grant
         *
         * /var/run/PolicyKit/session_<session>_<uid>_<action>_<resource-hash>.grant
         *                    session_<session>_<uid>_<action>.grant
         *                    dbus_<dbusname>_<uid>_<action>_<resource-hash>.grant
         */

        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/dbus_%s_%d_%s_%u.grant", 
                                      dbus_name, invoking_user_id, action_name, resource_hash);
        if (g_file_test (grant_file, G_FILE_TEST_EXISTS)) {
                result = POLKIT_RESULT_YES;
                g_free (grant_file);
                goto out;
        }
        g_free (grant_file);

        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/session_%s_%d_%s_%u.grant", 
                                      session_name, invoking_user_id, action_name, resource_hash);
        if (g_file_test (grant_file, G_FILE_TEST_EXISTS)) {
                result = POLKIT_RESULT_YES;
                g_free (grant_file);
                goto out;
        }
        g_free (grant_file);

        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit/uid_%d_%s_%u.grant", 
                                      invoking_user_id, action_name, resource_hash);
        if (g_file_test (grant_file, G_FILE_TEST_EXISTS)) {
                result = POLKIT_RESULT_YES;
                g_free (grant_file);
                goto out;
        }
        g_free (grant_file);


out:
        return result;
}

polkit_bool_t
polkit_module_set_functions (PolKitModuleInterface *module_interface)
{
        polkit_bool_t ret;

        ret = FALSE;
        if (module_interface == NULL)
                goto out;

        polkit_module_set_func_initialize (module_interface, _module_init);
        polkit_module_set_func_shutdown (module_interface, _module_shutdown);
        polkit_module_set_func_can_session_access_resource (module_interface, _module_can_session_access_resource);
        polkit_module_set_func_can_caller_access_resource (module_interface, _module_can_caller_access_resource);

        ret = TRUE;
out:
        return ret;
}

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-module-run-program.c : determine policy by running a program
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

#include <polkit/polkit.h>
#include <glib.h>

/* The symbol that polkit looks up when loading this module */
polkit_bool_t polkit_module_set_functions (PolKitModuleInterface *module_interface);

typedef struct {
        int program_argc;
        char **program_argv;
} UserData;

static polkit_bool_t
_module_init (PolKitModuleInterface *module_interface, int argc, char *argv[])
{
        int n;
        UserData *user_data;

        user_data = g_new0 (UserData, 1);
        for (n = 1; n < argc; n++) {
                if (g_str_has_prefix (argv[n], "program=")) {
                        const char *program;
                        program = argv[n] + 8;

                        if (!g_shell_parse_argv (program, 
                                                 &user_data->program_argc, 
                                                 &user_data->program_argv, NULL)) {
                                g_warning ("Cannot parse '%s' - skipping", program);
                                goto error;
                        }

                        if (!g_file_test (user_data->program_argv[0], 
                                          G_FILE_TEST_IS_EXECUTABLE|G_FILE_TEST_IS_REGULAR)) {
                                g_warning ("Program '%s' is not an executable file - skipping",
                                           user_data->program_argv[0]);
                                goto error;
                        }

                        g_debug ("program = '%s'", user_data->program_argv[0]);

                        /* TODO:
                         * O_o o_O... we could monitor the executable file :-) and trigger config changes!
                         */
                }
        }

        if (user_data->program_argv == NULL)
                goto error;

        polkit_module_set_user_data (module_interface, user_data);

        return TRUE;
error:
        if (user_data->program_argv != NULL)
                g_strfreev (user_data->program_argv);
        g_free (user_data);
        return FALSE;
}

static void
_module_shutdown (PolKitModuleInterface *module_interface)
{
        UserData *user_data;
        user_data = polkit_module_get_user_data (module_interface);
        if (user_data != NULL) {
                if (user_data->program_argv != NULL)
                        g_strfreev (user_data->program_argv);
                g_free (user_data);
        }
}

static polkit_bool_t
_add_action_to_env (PolKitAction *action, GPtrArray *envp)
{
        char *p_id;
        if (!polkit_action_get_action_id (action, &p_id))
                goto error;
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_ACTION_ID=%s", p_id));
        return TRUE;
error:
        return FALSE;
}

static polkit_bool_t
_add_resource_to_env (PolKitResource *resource, GPtrArray *envp)
{
        char *r_type;
        char *r_id;
        if (!polkit_resource_get_resource_type (resource, &r_type))
                goto error;
        if (!polkit_resource_get_resource_id (resource, &r_id))
                goto error;
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_RESOURCE_TYPE=%s", r_type));
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_RESOURCE_ID=%s", r_id));
        return TRUE;
error:
        return FALSE;
}

static polkit_bool_t
_add_seat_to_env (PolKitSeat *seat, GPtrArray *envp)
{
        char *s_ck_objref;
        if (!polkit_seat_get_ck_objref (seat, &s_ck_objref))
                goto error;
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_SEAT_CK_OBJREF=%s", s_ck_objref));
        return TRUE;
error:
        return FALSE;
}

static polkit_bool_t
_add_session_to_env (PolKitSession *session, GPtrArray *envp)
{
        uid_t s_uid;
        char *s_ck_objref;
        polkit_bool_t s_ck_is_active;
        polkit_bool_t s_ck_is_local;
        char *s_ck_remote_host;
        PolKitSeat *s_seat;

        if (!polkit_session_get_uid (session, &s_uid))
                goto error;
        if (!polkit_session_get_ck_objref (session, &s_ck_objref))
                goto error;
        if (!polkit_session_get_ck_is_active (session, &s_ck_is_active))
                goto error;
        if (!polkit_session_get_ck_is_local (session, &s_ck_is_local))
                goto error;
        if (!s_ck_is_local)
                if (!polkit_session_get_ck_remote_host (session, &s_ck_remote_host))
                        goto error;
        if (!polkit_session_get_seat (session, &s_seat))
                goto error;

        if (!_add_seat_to_env (s_seat, envp))
                goto error;
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_SESSION_UID=%d", (int) s_uid));
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_SESSION_CK_OBJREF=%s", s_ck_objref));
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_SESSION_CK_IS_ACTIVE=%d", s_ck_is_active));
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_SESSION_CK_IS_LOCAL=%d", s_ck_is_local));
        if (!s_ck_is_local)
                g_ptr_array_add (envp, g_strdup_printf ("POLKIT_SESSION_CK_REMOTE_HOST=%s", s_ck_remote_host));
        return TRUE;
error:
        return FALSE;
}

static polkit_bool_t
_add_caller_to_env (PolKitCaller *caller, GPtrArray *envp)
{
        uid_t c_uid;
        pid_t c_pid;
        char *c_selinux_context;
        char *c_dbus_name;
        PolKitSession *c_session;

        if (!polkit_caller_get_uid (caller, &c_uid))
                goto error;
        if (!polkit_caller_get_pid (caller, &c_pid))
                goto error;
        if (!polkit_caller_get_dbus_name (caller, &c_dbus_name))
                goto error;
        if (!polkit_caller_get_selinux_context (caller, &c_selinux_context)) /* SELinux may not be available */
                c_selinux_context = NULL;
        if (!polkit_caller_get_ck_session (caller, &c_session)) /* Caller may not originate from a session */
                c_session = NULL;

        if (c_session != NULL)
                if (!_add_session_to_env (c_session, envp))
                        goto error;
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_CALLER_UID=%d", (int) c_uid));
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_CALLER_PID=%d", (int) c_pid));
        g_ptr_array_add (envp, g_strdup_printf ("POLKIT_CALLER_DBUS_NAME=%s", c_dbus_name));
        if (c_selinux_context != NULL)
                g_ptr_array_add (envp, g_strdup_printf ("POLKIT_CALLER_SELINUX_CONTEXT=%s", c_selinux_context));
        return TRUE;
error:
        return FALSE;
}

static polkit_bool_t
_run_program (UserData *user_data, char **envp, PolKitResult *result)
{
        int n;
        int exit_status;
        GError *g_error;
        char *prog_stdout;
        polkit_bool_t ret;

        g_error = NULL;
        prog_stdout = NULL;
        ret = FALSE;

        if (!g_spawn_sync ("/",
                           user_data->program_argv,
                           envp,
                           0,
                           NULL,
                           NULL,
                           &prog_stdout,
                           NULL,
                           &exit_status,
                           &g_error)) {
                g_warning ("error spawning '%s': %s", user_data->program_argv[0], g_error->message);
                g_error_free (g_error);
                goto error;
        }

        /* only care if the program returned 0 */
        if (exit_status != 0)
                goto error;

        /* only care about the first line */
        for (n = 0; prog_stdout[n] != '\n' && prog_stdout[n] != '\0'; n++)
                ;
        prog_stdout[n] = '\0';

        if (!polkit_result_from_string_representation (prog_stdout, result)) {
                g_warning ("malformed result '%s' from program", prog_stdout);
                goto error;
        }

        ret = TRUE;
error:
        g_free (prog_stdout);
        return ret;
}


static PolKitResult
_module_can_session_access_resource (PolKitModuleInterface *module_interface,
                                     PolKitContext         *pk_context,
                                     PolKitAction          *action,
                                     PolKitResource        *resource,
                                     PolKitSession         *session)
{
        PolKitResult result;
        UserData *user_data;
        GPtrArray *envp;

        envp = NULL;
        result = POLKIT_RESULT_UNKNOWN_ACTION;

        user_data = polkit_module_get_user_data (module_interface);

        envp = g_ptr_array_new ();

        if (!_add_action_to_env (action, envp))
                goto error;
        if (resource != NULL)
                if (!_add_resource_to_env (resource, envp))
                        goto error;
        if (!_add_session_to_env (session, envp))
                goto error;
        g_ptr_array_add (envp, g_strdup ("PATH=/usr/bin:/bin"));
        g_ptr_array_add (envp, g_strdup ("POLKIT_REQUEST_SESSION=1"));
        g_ptr_array_add (envp, NULL);

        if (!_run_program (user_data, (char **) envp->pdata, &result))
                goto error;
        
error:
        if (envp != NULL) {
                g_ptr_array_foreach (envp, (GFunc) g_free, NULL);
                g_ptr_array_free (envp, TRUE);
        }
        return result;
}

static PolKitResult
_module_can_caller_access_resource (PolKitModuleInterface *module_interface,
                                    PolKitContext         *pk_context,
                                    PolKitAction          *action,
                                    PolKitResource        *resource,
                                    PolKitCaller          *caller)
{
        PolKitResult result;
        UserData *user_data;
        GPtrArray *envp;

        envp = NULL;
        result = POLKIT_RESULT_NO;
        user_data = polkit_module_get_user_data (module_interface);

        envp = g_ptr_array_new ();
        if (!_add_action_to_env (action, envp))
                goto error;
        if (resource != NULL)
                if (!_add_resource_to_env (resource, envp))
                        goto error;
        if (!_add_caller_to_env (caller, envp))
                goto error;
        g_ptr_array_add (envp, g_strdup ("PATH=/usr/bin:/bin"));
        g_ptr_array_add (envp, g_strdup ("POLKIT_REQUEST_CALLER=1"));
        g_ptr_array_add (envp, NULL);
        if(!_run_program (user_data, (char **) envp->pdata, &result))
                goto error;

error:
        if (envp != NULL) {
                g_ptr_array_foreach (envp, (GFunc) g_free, NULL);
                g_ptr_array_free (envp, TRUE);
        }
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

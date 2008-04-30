/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant.c : library for obtaining privileges
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
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#include <glib.h>
#include "polkit-grant.h"
#include "polkit-grant-test.h"

/**
 * SECTION:polkit-grant
 * @title: Authorizations and Authentication
 * @short_description: Obtain authorizations through
 * authentication.
 *
 * These functions are used to obtain authorizations for a user that
 * is able to successfully authenticate. It is only useful for people
 * writing user interfaces that interfaces with the end user.
 *
 * All of these functions are in the
 * <literal>libpolkit-grant</literal> library.
 **/

/**
 * PolKitGrant:
 *
 * Objects of this class are used to obtain authorizations for a user
 * that is able to successfully authenticate. It is only useful for
 * people writing user interfaces that interfaces with the end user.
 *
 * All of these functions are in the
 * <literal>libpolkit-grant</literal> library.
 **/
struct _PolKitGrant
{
        int refcount;

        PolKitGrantAddIOWatch func_add_io_watch;
        PolKitGrantAddChildWatch func_add_child_watch;
        PolKitGrantRemoveWatch func_remove_watch;
        PolKitGrantType func_type;
        PolKitGrantSelectAdminUser func_select_admin_user;
        PolKitGrantConversationPromptEchoOff func_prompt_echo_off;
        PolKitGrantConversationPromptEchoOn func_prompt_echo_on;
        PolKitGrantConversationErrorMessage func_error_message;
        PolKitGrantConversationTextInfo func_text_info;
        PolKitGrantOverrideGrantType func_override_grant_type;
        PolKitGrantDone func_done;
        void *user_data;

        int child_stdin;
        int child_stdout;
        GPid child_pid;
        FILE *child_stdout_f;

        int child_watch_id;
        int io_watch_id;

        gboolean success;
        gboolean helper_is_running;
};

/**
 * polkit_grant_new:
 * 
 * Creates a #PolKitGrant object.
 * 
 * This function is in <literal>libpolkit-grant</literal>.
 *
 * Returns: the new object or #NULL if the authorization backend
 * doesn't support obtaining authorizations through authentication.
 **/
PolKitGrant *
polkit_grant_new (void)
{
        PolKitGrant *polkit_grant;

        if (! (polkit_authorization_db_get_capabilities () & POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN))
                return NULL;

        polkit_grant = g_new0 (PolKitGrant, 1);
        polkit_grant->refcount = 1;
        return polkit_grant;
}

/**
 * polkit_grant_ref:
 * @polkit_grant: the object
 * 
 * Increase reference count.
 * 
 * This function is in <literal>libpolkit-grant</literal>.
 *
 * Returns: the object.
 **/
PolKitGrant *
polkit_grant_ref (PolKitGrant *polkit_grant)
{
        g_return_val_if_fail (polkit_grant != NULL, NULL);

        polkit_grant->refcount++;
        return polkit_grant;
}

/**
 * polkit_grant_unref:
 * @polkit_grant: the object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 *
 * This function is in <literal>libpolkit-grant</literal>.
 **/
void
polkit_grant_unref (PolKitGrant *polkit_grant)
{
        g_return_if_fail (polkit_grant != NULL);

        polkit_grant->refcount--;
        if (polkit_grant->refcount > 0) 
                return;

        if (polkit_grant->io_watch_id > 0) {
                polkit_grant->func_remove_watch (polkit_grant, polkit_grant->io_watch_id);
        }
        if (polkit_grant->child_watch_id > 0) {
                polkit_grant->func_remove_watch (polkit_grant, polkit_grant->child_watch_id);
        }
        if (polkit_grant->child_pid > 0) {
                int status;
                kill (polkit_grant->child_pid, SIGTERM);
                waitpid (polkit_grant->child_pid, &status, 0);
        }
        if (polkit_grant->child_stdout_f != NULL) {
                fclose (polkit_grant->child_stdout_f);
        }
        if (polkit_grant->child_stdout >= 0) {
                close (polkit_grant->child_stdout);
        }
        if (polkit_grant->child_stdin >= 0) {
                close (polkit_grant->child_stdin);
        }

        g_free (polkit_grant);
}

/**
 * polkit_grant_set_functions:
 * @polkit_grant: the object
 * @func_add_io_watch: Callback function
 * @func_add_child_watch: Callback function
 * @func_remove_watch: Callback function
 * @func_type: Callback function
 * @func_select_admin_user: Callback function
 * @func_prompt_echo_off: Callback function
 * @func_prompt_echo_on: Callback function
 * @func_error_message: Callback function
 * @func_text_info: Callback function
 * @func_override_grant_type: Callback function
 * @func_done: Callback function
 * @user_data: User data that will be passed to the callback functions.
 * 
 * Set callback functions used for authentication.
 *
 * This function is in <literal>libpolkit-grant</literal>.
 **/
void
polkit_grant_set_functions (PolKitGrant *polkit_grant,
                            PolKitGrantAddIOWatch func_add_io_watch,
                            PolKitGrantAddChildWatch func_add_child_watch,
                            PolKitGrantRemoveWatch func_remove_watch,
                            PolKitGrantType func_type,
                            PolKitGrantSelectAdminUser func_select_admin_user,
                            PolKitGrantConversationPromptEchoOff func_prompt_echo_off,
                            PolKitGrantConversationPromptEchoOn func_prompt_echo_on,
                            PolKitGrantConversationErrorMessage func_error_message,
                            PolKitGrantConversationTextInfo func_text_info,
                            PolKitGrantOverrideGrantType func_override_grant_type,
                            PolKitGrantDone func_done,
                            void *user_data)
{
        g_return_if_fail (polkit_grant != NULL);
        g_return_if_fail (func_add_io_watch != NULL);
        g_return_if_fail (func_add_child_watch != NULL);
        g_return_if_fail (func_remove_watch != NULL);
        g_return_if_fail (func_type != NULL);
        g_return_if_fail (func_select_admin_user != NULL);
        g_return_if_fail (func_prompt_echo_off != NULL);
        g_return_if_fail (func_prompt_echo_on != NULL);
        g_return_if_fail (func_error_message != NULL);
        g_return_if_fail (func_text_info != NULL);
        g_return_if_fail (func_override_grant_type != NULL);
        polkit_grant->func_add_io_watch = func_add_io_watch;
        polkit_grant->func_add_child_watch = func_add_child_watch;
        polkit_grant->func_remove_watch = func_remove_watch;
        polkit_grant->func_type = func_type;
        polkit_grant->func_select_admin_user = func_select_admin_user;
        polkit_grant->func_prompt_echo_off = func_prompt_echo_off;
        polkit_grant->func_prompt_echo_on = func_prompt_echo_on;
        polkit_grant->func_error_message = func_error_message;
        polkit_grant->func_text_info = func_text_info;
        polkit_grant->func_override_grant_type = func_override_grant_type;
        polkit_grant->func_done = func_done;
        polkit_grant->user_data = user_data;
}


/**
 * polkit_grant_child_func:
 * @polkit_grant: the object
 * @pid: pid of the child
 * @exit_code: exit code of the child
 * 
 * Method that the application must call when a child process
 * registered with the supplied function of type
 * #PolKitGrantAddChildWatch terminates.
 *
 * This function is in <literal>libpolkit-grant</literal>.
 **/
void
polkit_grant_child_func (PolKitGrant *polkit_grant, pid_t pid, int exit_code)
{
        int status;
        polkit_bool_t input_was_bogus;

        g_return_if_fail (polkit_grant != NULL);
        g_return_if_fail (polkit_grant->helper_is_running);

        /* g_debug ("pid %d terminated", pid); */
        waitpid (pid, &status, 0);

        if (exit_code >= 2)
                input_was_bogus = TRUE;
        else
                input_was_bogus = FALSE;

        polkit_grant->success = (exit_code == 0);
        polkit_grant->helper_is_running = FALSE;
        polkit_grant->func_done (polkit_grant, polkit_grant->success, input_was_bogus, polkit_grant->user_data);
}


/**
 * polkit_grant_io_func:
 * @polkit_grant: the object
 * @fd: the file descriptor passed to the supplied function of type #PolKitGrantAddIOWatch.
 * 
 * Method that the application must call when there is data to read
 * from a file descriptor registered with the supplied function of
 * type #PolKitGrantAddIOWatch.
 *
 * This function is in <literal>libpolkit-grant</literal>.
 **/
void 
polkit_grant_io_func (PolKitGrant *polkit_grant, int fd)
{
        char *line = NULL;
        size_t line_len = 0;
        char *id;
        size_t id_len;
        char *response;
        char *response_prefix;

        g_return_if_fail (polkit_grant != NULL);
        g_return_if_fail (polkit_grant->helper_is_running);

        while (kit_getline (&line, &line_len, polkit_grant->child_stdout_f) != -1) {
                if (strlen (line) > 0 &&
                    line[strlen (line) - 1] == '\n')
                        line[strlen (line) - 1] = '\0';
                
                response = NULL;
                response_prefix = NULL;
                
                id = "PAM_PROMPT_ECHO_OFF ";
                if (g_str_has_prefix (line, id)) {
                        id_len = strlen (id);
                        response_prefix = "";
                        response = polkit_grant->func_prompt_echo_off (polkit_grant, 
                                                                       line + id_len, 
                                                                       polkit_grant->user_data);
                        goto processed;
                }
                
                id = "PAM_PROMPT_ECHO_ON ";
                if (g_str_has_prefix (line, id)) {
                        id_len = strlen (id);
                        response_prefix = "";
                        response = polkit_grant->func_prompt_echo_on (polkit_grant, 
                                                                      line + id_len, 
                                                                      polkit_grant->user_data);
                        goto processed;
                }
                
                id = "PAM_ERROR_MSG ";
                if (g_str_has_prefix (line, id)) {
                        id_len = strlen (id);
                        polkit_grant->func_error_message (polkit_grant, 
                                                          line + id_len, 
                                                          polkit_grant->user_data);
                        goto processed;
                }
                
                id = "PAM_TEXT_INFO ";
                if (g_str_has_prefix (line, id)) {
                        id_len = strlen (id);
                        polkit_grant->func_text_info (polkit_grant, 
                                                      line + id_len, 
                                                      polkit_grant->user_data);
                        goto processed;
                }
                
                id = "POLKIT_GRANT_HELPER_TELL_TYPE ";
                if (g_str_has_prefix (line, id)) {
                        PolKitResult result;
                        char *result_textual;

                        id_len = strlen (id);
                        result_textual = line + id_len;
                        if (!polkit_result_from_string_representation (result_textual, &result)) {
                                /* TODO: danger will robinson */
                        }

                        polkit_grant->func_type (polkit_grant, 
                                                 result,
                                                 polkit_grant->user_data);
                        goto processed;
                }

                id = "POLKIT_GRANT_HELPER_TELL_ADMIN_USERS ";
                if (g_str_has_prefix (line, id)) {
                        char **admin_users;

                        id_len = strlen (id);
                        admin_users = g_strsplit (line + id_len, " ", 0);

                        response_prefix = "POLKIT_GRANT_CALLER_SELECT_ADMIN_USER ";
                        response = polkit_grant->func_select_admin_user (polkit_grant, 
                                                                         admin_users,
                                                                         polkit_grant->user_data);
                        g_strfreev (admin_users);

                        goto processed;
                }

                id = "POLKIT_GRANT_HELPER_ASK_OVERRIDE_GRANT_TYPE ";
                if (g_str_has_prefix (line, id)) {
                        PolKitResult override;
                        PolKitResult result;
                        id_len = strlen (id);
                        if (!polkit_result_from_string_representation (line + id_len, &result)) {
                                /* TODO: danger will robinson */
                        }
                        override = polkit_grant->func_override_grant_type (polkit_grant, 
                                                                           result, 
                                                                           polkit_grant->user_data);
                        response_prefix = "POLKIT_GRANT_CALLER_PASS_OVERRIDE_GRANT_TYPE ";
                        response = g_strdup (polkit_result_to_string_representation (override));
                        goto processed;
                }

        processed:
                if (response != NULL && response_prefix != NULL) {
                        char *buf;
                        gboolean add_newline;

                        /* add a newline if there isn't one already... */
                        add_newline = FALSE;
                        if (response[strlen (response) - 1] != '\n') {
                                add_newline = TRUE;
                        }
                        buf = g_strdup_printf ("%s%s%c",
                                               response_prefix,
                                               response,
                                               add_newline ? '\n' : '\0');
                        write (polkit_grant->child_stdin, buf, strlen (buf));
                        g_free (buf);
                        free (response);
                }
        }

        if (line != NULL)
                free (line);
}

/**
 * polkit_grant_cancel_auth:
 * @polkit_grant: the object
 * 
 * Cancel an authentication in progress
 *
 * This function is in <literal>libpolkit-grant</literal>.
 **/
void
polkit_grant_cancel_auth (PolKitGrant *polkit_grant)
{
        GPid pid;
        g_return_if_fail (polkit_grant != NULL);
        g_return_if_fail (polkit_grant->helper_is_running);

        pid = polkit_grant->child_pid;
        polkit_grant->child_pid = 0;
        if (pid > 0) {
                int status;
                kill (pid, SIGTERM);
                waitpid (pid, &status, 0);
                polkit_grant->helper_is_running = FALSE;
        }
        polkit_grant->func_done (polkit_grant, FALSE, FALSE, polkit_grant->user_data);        
}

/**
 * polkit_grant_initiate_auth:
 * @polkit_grant: the object
 * @action: Action requested by caller
 * @caller: Caller in question
 * 
 * Initiate authentication to obtain the privilege for the given
 * @caller to perform the specified @action. The caller of this method
 * must have setup callback functions using the method
 * polkit_grant_set_functions() prior to calling this method.
 *
 * Implementation-wise, this class uses a secure (e.g. as in that it
 * checks all information and fundamenally don't trust the caller;
 * e.g. the #PolKitGrant class) setgid helper that does all the heavy
 * lifting.
 *
 * The caller of this method must iterate the mainloop context in
 * order for authentication to make progress.
 *
 * This function is in <literal>libpolkit-grant</literal>.
 *
 * Returns: #TRUE only if authentication have been initiated.
 **/
polkit_bool_t 
polkit_grant_initiate_auth (PolKitGrant  *polkit_grant,
                            PolKitAction *action,
                            PolKitCaller *caller)
{
        pid_t pid;
        char *action_id;
        GError *g_error;
        char *helper_argv[4];

        g_return_val_if_fail (polkit_grant != NULL, FALSE);
        /* check that callback functions have been properly set up */
        g_return_val_if_fail (polkit_grant->func_done != NULL, FALSE);

        if (!polkit_caller_get_pid (caller, &pid))
                goto error;

        if (!polkit_action_get_action_id (action, &action_id))
                goto error;

        /* TODO: verify incoming args */

        /* helper_argv[0] = "/home/davidz/Hacking/PolicyKit/polkit-grant/.libs/polkit-grant-helper"; */
        helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-grant-helper";
        helper_argv[1] = g_strdup_printf ("%d", pid);
        helper_argv[2] = action_id;
        helper_argv[3] = NULL;

        polkit_grant->child_stdin = -1;
        polkit_grant->child_stdout = -1;

        g_error = NULL;
        if (!g_spawn_async_with_pipes (NULL,
                                       (char **) helper_argv,
                                       NULL,
                                       G_SPAWN_DO_NOT_REAP_CHILD |
                                       0,//G_SPAWN_STDERR_TO_DEV_NULL,
                                       NULL,
                                       NULL,
                                       &polkit_grant->child_pid,
                                       &polkit_grant->child_stdin,
                                       &polkit_grant->child_stdout,
                                       NULL,
                                       &g_error)) {
                fprintf (stderr, "Cannot spawn helper: %s.\n", g_error->message);
                g_error_free (g_error);
                g_free (helper_argv[1]);
                goto error;
        }
        g_free (helper_argv[1]);

        polkit_grant->child_watch_id = polkit_grant->func_add_child_watch (polkit_grant, polkit_grant->child_pid);
        if (polkit_grant->child_watch_id == 0)
                goto error;

        polkit_grant->io_watch_id = polkit_grant->func_add_io_watch (polkit_grant, polkit_grant->child_stdout);
        if (polkit_grant->io_watch_id == 0)
                goto error;

        /* so we can use getline... */
        polkit_grant->child_stdout_f = fdopen (polkit_grant->child_stdout, "r");
        if (polkit_grant->child_stdout_f == NULL)
                goto error;
        
        polkit_grant->success = FALSE;

        polkit_grant->helper_is_running = TRUE;

        return TRUE;
error:
        return FALSE;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_polkit_grant = {
        "polkit_grant",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-simple.c : Simple convenience interface
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

/**
 * SECTION:polkit-simple
 * @title: Simple convenience interface
 * @short_description: Simple convenience interface
 *
 * Simple convenience interface
 **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <polkit/polkit-private.h>
#include "polkit-simple.h"
#include "polkit-dbus.h"


/**
 * polkit_check_auth:
 * @pid: process to check for; typically you want to pass the result of getpid() here
 * @...: %NULL terminated list of action identifiers to check for
 *
 * A simple convenience function to check whether a given process is
 * authorized for a number of actions. 
 *
 * This is useful for programs that just wants to check whether they
 * should carry out some action. Note that the user identity used for
 * the purpose of checking authorizations is the Real one compared to
 * the e.g. Effective one (e.g. getuid(), getgid() is used instead of
 * e.g. geteuid(), getegid()). This is typically what one wants in a
 * setuid root program if the setuid root program is designed to do
 * work on behalf of the unprivileged user who invoked it (for
 * example, the PulseAudio sound server is setuid root only so it can
 * become a real time process; after that it drops all privileges).
 *
 * It varies whether one wants to pass getpid() or getppid() as the
 * process id to this function. For example, in the PulseAudio case it
 * is the right thing to pass getpid(). However, in a setup where the
 * process is a privileged helper, one wants to pass the process id of
 * the parent. Beware though, if the parent dies, getppid() will
 * return 1 (the process id of <literal>/sbin/init</literal>) which is
 * almost certainly guaranteed to be privileged as it is running as
 * uid 0.
 *
 * Note that this function will open a connection to the system
 * message bus and query ConsoleKit for details. In addition, it will
 * load PolicyKit specific files and spawn privileged helpers if
 * necessary. As such, there is a bit of IPC, context switching,
 * syscall overhead and I/O involved in using this function. If you
 * are planning on calling this function multiple times (e.g. from a
 * daemon) on a frequent basis and/or need more detail you should use
 * the #PolKitContext and #PolKitTracker classes instead as these are
 * designed to aggresively cache information.
 *
 * The return value is a bit mask indicating whether the given process
 * is authorized for the given actions. Bit 0 represents the first
 * action; bit 1 represents the 2nd action and so forth. A bit is set
 * to 1 if, and only if, the caller is authorized for the given
 * action. If the given action is unknown zero will be returned as well.
 *
 * If the function succeeds, errno will be set to 0. If an error
 * occurs 0 is returned and errno will be set:
 * <itemizedlist>
 * <listitem><literal>ENOMEM</literal>: Out of memory.</listitem>
 * <listitem><literal>ENOENT</literal>: Failed to connect to either the system message bus or ConsoleKit.</listitem>
 * </itemizedlist>
 *
 * Returns: See above
 *
 * Since: 0.7
 */
polkit_uint64_t 
polkit_check_auth (pid_t pid, ...)
{
        int n;
        va_list args;
        char *action_id;
        polkit_uint64_t ret;
        const char *action_ids[65];

        ret = 0;

        n = 0;
        va_start (args, pid);
        while ((action_id = va_arg (args, char *)) != NULL) {
                if (n == 64) {
                        errno = EOVERFLOW;
                        goto out;
                }
                action_ids[n++] = action_id;
        }
        va_end (args);
        action_ids[n] = NULL;

        ret = polkit_check_authv (pid, action_ids); 
out:
        return ret;
}

/**
 * polkit_check_authv:
 * @pid: See docs for polkit_check_auth()
 * @action_ids: %NULL terminated array of action id's
 *
 * This function is similar to polkit_check_auth() but takes an %NULL
 * terminated array instead of being a varadic function.
 *
 * Returns: See docs for polkit_check_auth()
 *
 * Since: 0.7
 */
polkit_uint64_t 
polkit_check_authv (pid_t pid, const char **action_ids)
{
        int n;
        polkit_uint64_t ret;
        DBusError error;
        DBusConnection *bus;
        PolKitCaller *caller;
        PolKitContext *context;
        PolKitError *pk_error;
        PolKitResult pk_result;

        ret = 0;
        errno = ENOENT;
        context = NULL;
        caller = NULL;
        bus = NULL;

        dbus_error_init (&error);

#ifdef POLKIT_BUILD_TESTS
        char *pretend;
        if ((pretend = getenv ("POLKIT_TEST_PRETEND_TO_BE_CK_SESSION_OBJPATH")) != NULL) {
                /* see polkit_caller_new_from_pid() - basically, it's 
                 * if POLKIT_TEST_PRETEND_TO_BE_CK_SESSION_OBJPATH is set
                 * then the bus won't be used at all
                 */
                goto no_bus;
        }
#endif
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                kit_warning ("cannot connect to system bus: %s: %s", error.name, error.message);
                dbus_error_free (&error);
                goto out;
        }
#ifdef POLKIT_BUILD_TESTS
no_bus:
#endif

        caller = polkit_caller_new_from_pid (bus, pid, &error);
        if (caller == NULL) {
                kit_warning ("cannot get caller from pid: %s: %s", error.name, error.message);
                goto out;
        }

        context = polkit_context_new ();
        if (context == NULL) {
                kit_warning ("cannot allocate PolKitContext");
                errno = ENOMEM;
                goto out;
        }

        pk_error = NULL;
        if (!polkit_context_init (context, &pk_error)) {
                kit_warning ("cannot initialize polkit context: %s: %s",
                             polkit_error_get_error_name (pk_error),
                             polkit_error_get_error_message (pk_error));
                polkit_error_free (pk_error);
                goto out;
        }

        for (n = 0; action_ids[n] != NULL; n++) {
                PolKitAction *action;

                action = polkit_action_new ();
                if (action == NULL) {
                        kit_warning ("cannot allocate PolKitAction");
                        errno = ENOMEM;
                        goto out;
                }
                if (!polkit_action_set_action_id (action, action_ids[n])) {
                        polkit_action_unref (action);
                        kit_warning ("cannot set action_id");
                        errno = ENOMEM;
                        goto out;
                }
                
                pk_error = NULL;
                pk_result = polkit_context_is_caller_authorized (context, action, caller, FALSE, &pk_error);

                if (polkit_error_is_set (pk_error)) {
                        polkit_error_free (pk_error);
                        pk_error = NULL;
                } else {
                        if (pk_result == POLKIT_RESULT_YES)
                                ret |= (1<<n);
                }

                polkit_action_unref (action);
        }

out:
        if (bus != NULL)
                dbus_connection_unref (bus);
        if (caller != NULL)
                polkit_caller_unref (caller);
        if (context != NULL)
                polkit_context_unref (context);

        return ret;
}

extern char **environ;

static polkit_bool_t
_auth_show_dialog_text (const char *action_id, pid_t pid, DBusError *error)
{
        unsigned int n;
        polkit_bool_t ret;
        int exit_status;
        char *helper_argv[] = {PACKAGE_BIN_DIR "/polkit-auth", "--obtain", NULL, NULL};
        char **envp;
        size_t envsize;
        char buf[256];

        ret = FALSE;

        if (isatty (STDOUT_FILENO) != 1 || isatty (STDIN_FILENO) != 1) {
                dbus_set_error (error, 
                                "org.freedesktop.PolicyKit.LocalError",
                                "stdout and/or stdin is not a tty");
                goto out;
        }

        envsize = kit_strv_length (environ);
        envp = kit_new0 (char *, envsize + 3);
        if (envp == NULL)
                goto out;
        for (n = 0; n < envsize; n++)
                envp[n] = environ[n];
        envp[envsize] = "POLKIT_AUTH_FORCE_TEXT=1";
        snprintf (buf, sizeof (buf), "POLKIT_AUTH_GRANT_TO_PID=%d", pid);
        envp[envsize+1] = buf;

        helper_argv[2] = (char *) action_id;

        if (!kit_spawn_sync (NULL,                           /* const char  *working_directory */
                             KIT_SPAWN_CHILD_INHERITS_STDIN, /* flags */
                             helper_argv,                    /* char       **argv */
                             envp,                           /* char       **envp */
                             NULL,                           /* char        *stdin */
                             NULL,                           /* char       **stdout */
                             NULL,                           /* char       **stderr */
                             &exit_status)) {                /* int         *exit_status */
                dbus_set_error (error, 
                                "org.freedesktop.PolicyKit.LocalError",
                                "Error spawning polkit-auth: %m");
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                dbus_set_error (error, 
                                "org.freedesktop.PolicyKit.LocalError",
                                "polkit-auth crashed!");
                goto out;
        } else if (WEXITSTATUS(exit_status) != 0) {
                goto out;
        }

        ret = TRUE;

out:
        return ret;
}

/**
 * polkit_auth_obtain: 
 * @action_id: The action_id for the #PolKitAction to make the user
 * authenticate for
 * @xid: X11 window ID for the window that the dialog will be
 * transient for. If there is no window, pass 0.
 * @pid: Process ID of process to grant authorization to. Normally one wants to pass result of getpid().
 * @error: return location for error; cannot be %NULL
 *
 * Convenience function to prompt the user to authenticate to gain an
 * authorization for the given action. First, an attempt to reach an
 * Authentication Agent on the session message bus is made. If that
 * doesn't work and stdout/stdin are both tty's, polkit-auth(1) is
 * invoked.
 *
 * This is a blocking call. If you're using GTK+ see
 * polkit_gnome_auth_obtain() for a non-blocking version.
 *
 * Returns: %TRUE if, and only if, the user successfully
 * authenticated. %FALSE if the user failed to authenticate or if
 * error is set
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_auth_obtain (const char *action_id, polkit_uint32_t xid, pid_t pid, DBusError *error)
{
        polkit_bool_t ret;
        DBusConnection *bus;
        DBusMessage *message;
        DBusMessage *reply;

        kit_return_val_if_fail (action_id != NULL, FALSE);
        kit_return_val_if_fail (error != NULL, FALSE);
        kit_return_val_if_fail (!dbus_error_is_set (error), FALSE);

        bus = NULL;
        message = NULL;
        reply = NULL;
        ret = FALSE;

        bus = dbus_bus_get (DBUS_BUS_SESSION, error);
        if (bus == NULL) {
                dbus_error_init (error);
                ret = _auth_show_dialog_text (action_id, pid, error);
                goto out;
        }

	message = dbus_message_new_method_call ("org.freedesktop.PolicyKit.AuthenticationAgent", /* service */
						"/",                                             /* object path */
						"org.freedesktop.PolicyKit.AuthenticationAgent", /* interface */
						"ObtainAuthorization");
	dbus_message_append_args (message, 
                                  DBUS_TYPE_STRING, &action_id, 
                                  DBUS_TYPE_UINT32, &xid, 
                                  DBUS_TYPE_UINT32, &pid,
                                  DBUS_TYPE_INVALID);
	reply = dbus_connection_send_with_reply_and_block (bus, message, -1, error);
	if (reply == NULL || dbus_error_is_set (error)) {
                ret = _auth_show_dialog_text (action_id, pid, error);
		goto out;
	}
	if (!dbus_message_get_args (reply, NULL,
				    DBUS_TYPE_BOOLEAN, &ret,
                                    DBUS_TYPE_INVALID)) {
                dbus_error_init (error);
                ret = _auth_show_dialog_text (action_id, pid, error);
		goto out;
	}

out:
        if (bus != NULL)
                dbus_connection_unref (bus);
        if (message != NULL)
                dbus_message_unref (message);
        if (reply != NULL)
                dbus_message_unref (reply);

        return ret;
}


#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_simple = {
        "polkit_simple",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

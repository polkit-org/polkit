/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-simple.c : Simple convenience interface
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
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <polkit/polkit-private.h>
#include "polkit-simple.h"


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

        dbus_error_init (&error);
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                kit_warning ("cannot connect to system bus: %s: %s", error.name, error.message);
                dbus_error_free (&error);
                goto out;
        }

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

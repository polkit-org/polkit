/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-sysdeps.c : Various platform specific utility functions
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_SOLARIS
#include <fcntl.h>
#include <sys/time.h>
#if _FILE_OFFSET_BITS==64
#undef _FILE_OFFSET_BITS
#include <procfs.h>
#define _FILE_OFFSET_BITS 64
#else
#include <procfs.h>
#endif
#elif defined(HAVE_INOTIFY)
#include <sys/inotify.h>
#endif
#include <syslog.h>

#include "polkit-sysdeps.h"
#include "polkit-private.h"
#include "polkit-test.h"

/**
 * SECTION:polkit-sysdeps
 * @title: System Dependencies
 * @short_description: Various platform specific utility functions
 *
 * Various platform specific utility functions.
 *
 * Since: 0.7
 **/


/**
 * polkit_sysdeps_get_start_time_for_pid:
 * @pid: process id
 *
 * Get when a process started.
 *
 * Returns: start time for the process or 0 if an error occured and errno will be set
 *
 * Since: 0.7
 */
polkit_uint64_t 
polkit_sysdeps_get_start_time_for_pid (pid_t pid)
{
        char *filename;
        char *contents;
        size_t length;
        polkit_uint64_t start_time;
#ifdef HAVE_SOLARIS
        struct psinfo info;
#else
        char **tokens;
        size_t num_tokens;
        char *p;
        char *endp;
#endif

        start_time = 0;
        contents = NULL;

#ifdef HAVE_SOLARIS
        if (polkit_sysdeps_pid_psinfo ( pid, &info)) {
                goto out;
        }
        start_time = (unsigned long long) (info.pr_start.tv_sec);
#else
#ifdef __FreeBSD__
	filename = kit_strdup_printf ("/proc/%d/status", pid);
#else
        filename = kit_strdup_printf ("/proc/%d/stat", pid);
#endif
        if (filename == NULL) {
                errno = ENOMEM;
                goto out;
        }

        if (!kit_file_get_contents (filename, &contents, &length)) {
                //fprintf (stderr, "Cannot get contents of '%s': %s\n", filename, error->message);
                goto out;
        }

#ifdef __FreeBSD__
        tokens = kit_strsplit (contents, ' ', &num_tokens);
        if (tokens == NULL)
                goto out;
        if (num_tokens < 8) {
                kit_strfreev (tokens);
                goto out;
        }

        p = kit_strdup (tokens[7]);
        kit_strfreev (tokens);

        tokens = kit_strsplit (p, ',', &num_tokens);
        kit_free (p);
        if (tokens == NULL)
                goto out;
        if (num_tokens >= 1) {
                start_time = strtoll (tokens[0], &endp, 10);
                if (endp == tokens[0]) {
                        kit_strfreev (tokens);
                        goto out;
                }
        } else {
                kit_strfreev (tokens);
                goto out;
        }

        kit_strfreev (tokens);
#else

        /* start time is the 19th token after the '(process name)' entry */

        p = strchr (contents, ')');
        if (p == NULL) {
                goto out;
        }
        p += 2; /* skip ') ' */
        if (p - contents >= (int) length) {
                goto out;
        }

        tokens = kit_strsplit (p, ' ', &num_tokens);
        if (tokens == NULL)
                goto out;

        if (num_tokens < 20) {
                goto out;
        }

        start_time = strtoll (tokens[19], &endp, 10);
        if (endp == tokens[19]) {
                goto out;
        }

        kit_strfreev (tokens);
#endif
#endif

out:
#ifndef HAVE_SOLARIS
        kit_free (filename);
        kit_free (contents);
#endif
        return start_time;
}

/**
 * polkit_sysdeps_get_exe_for_pid:
 * @pid: process id
 * @out_buf: buffer to store the string representation in
 * @buf_size: size of buffer
 *
 * Get the name of the binary a given process was started from.
 *
 * Note that this is not necessary reliable information and as such
 * shouldn't be relied on 100% to make a security decision. In fact,
 * this information is only trustworthy in situations where the given
 * binary is securely locked down meaning that 1) it can't be
 * <literal>ptrace(2)</literal>'d; 2) libc secure mode kicks in (e.g
 * <literal>LD_PRELOAD</literal> won't work); 3) there are no other
 * attack vectors (e.g. GTK_MODULES, X11, CORBA, D-Bus) to patch
 * running code into the process.
 *
 * In other words: the risk of relying on constraining an
 * authorization to the output of this function is high. Suppose that
 * the program <literal>/usr/bin/gullible</literal> obtains an
 * authorization via authentication for the action
 * <literal>org.example.foo</literal>. We add a constraint to say that
 * the gained authorization only applies to processes for whom
 * <literal>/proc/pid/exe</literal> points to
 * <literal>/usr/bin/gullible</literal>. Now enter
 * <literal>/usr/bin/evil</literal>. It knows that the program
 * <literal>/usr/bin/gullible</literal> is not "securely locked down"
 * (per the definition in the above paragraph). So
 * <literal>/usr/bin/evil</literal> simply sets
 * <literal>LD_PRELOAD</literal> and execs
 * <literal>/usr/bin/gullible</literal> and it can now run code in a
 * process where <literal>/proc/pid/exe</literal> points to
 * <literal>/usr/bin/gullible</literal>. Thus, the recently gained
 * authorization for <literal>org.example.foo</literal> applies. Also,
 * <literal>/usr/bin/evil</literal> could use a host of other attack
 * vectors to run it's own code under the disguise of pretending to be
 * <literal>/usr/bin/gullible</literal>.
 *
 * Specifically for interpreted languages like Python and Mono it is
 * the case that <literal>/proc/pid/exe</literal> always points to
 * <literal>/usr/bin/python</literal>
 * resp. <literal>/usr/bin/mono</literal>. Thus, it's not very useful
 * to rely on that the result for this function if you want to
 * constrain an authorization to
 * e.g. <literal>/usr/bin/tomboy</literal> or
 * <literal>/usr/bin/banshee</literal>.
 *
 * If the information could not be obtained, such as if the given
 * process is owned by another user than the caller, -1 is returned
 * and out_buf will be set to "(unknown)". See also the function
 * polkit_sysdeps_get_exe_for_pid_with_helper().
 *
 * Returns: Number of characters written (not including trailing
 * '\0'). If the output was truncated due to the buffer being too
 * small, buf_size will be returned. Thus, a return value of buf_size
 * or more indicates that the output was truncated (see snprintf(3))
 * or an error occured. If the name cannot be found, -1 will be
 * returned.
 *
 * Since: 0.7
 */
int
polkit_sysdeps_get_exe_for_pid (pid_t pid, char *out_buf, size_t buf_size)
{
        int ret;
        char proc_name[32];

        /* TODO: to avoid work we should maintain a cache. The key
         * into the cache should be (pid, pid_start_time) and the
         * values should be the exe-paths  
         */

        ret = 0;

#ifdef HAVE_SOLARIS
        struct psinfo info;

        if (polkit_sysdeps_pid_psinfo (pid, &info)) {
                goto out;
        }
        ret = strlen (info.pr_psargs);
        strncpy (out_buf, info.pr_psargs, ret);
#else
#ifdef __FreeBSD__
	snprintf (proc_name, sizeof (proc_name), "/proc/%d/file", pid);
#else
        snprintf (proc_name, sizeof (proc_name), "/proc/%d/exe", pid);
#endif
        ret = readlink (proc_name, out_buf, buf_size - 1);
        if (ret == -1) {
                strncpy (out_buf, "(unknown)", buf_size);
                goto out;
        }
#endif
        kit_assert (ret >= 0 && ret < (int) buf_size - 1);
        out_buf[ret] = '\0';

out:
        return ret;
}

/**
 * polkit_sysdeps_get_exe_for_pid_with_helper:
 * @pid: process id
 * @out_buf: buffer to store the string representation in
 * @buf_size: size of buffer
 *
 * Like polkit_sysdeps_get_exe_for_pid() but if the given process is
 * owned by another user, a setuid root helper is used to obtain the
 * information. This helper only works if 1) the caller is authorized
 * for the org.freedesktop.policykit.read authorization; or 2) the
 * calling user is polkituser; or 3) the calling user is setegid
 * polkituser.
 *
 * So -1 might still be returned (the process might also have exited).
 *
 * Returns: See polkit_sysdeps_get_exe_for_pid().
 *
 * Since: 0.8
 */
int 
polkit_sysdeps_get_exe_for_pid_with_helper (pid_t pid, char *out_buf, size_t buf_size)
{
        int ret;

        /* TODO: to avoid work we should maintain a cache. The key
         * into the cache should be (pid, pid_start_time) and the
         * values should be the exe-paths  
         */

        ret = polkit_sysdeps_get_exe_for_pid (pid, out_buf, buf_size);
        if (ret == -1) {
                char buf[32];
                char *helper_argv[3] = {PACKAGE_LIBEXEC_DIR "/polkit-resolve-exe-helper-1", buf, NULL};
                char *standard_output;
                int exit_status;

                /* Uh uh.. This means that we don't have permission to read /proc/$pid/exe for
                 * the given process id... this can happen if the mechanism in question runs
                 * as an unprivileged user instead of uid 0 (e.g. user 'haldaemon'). 
                 *
                 * This blows.
                 *
                 * To work around this we use a setuid root helper that
                 *
                 * 1. checks whether the caller (us) has the 1) org.freedesktop.policykit.read
                 *    authorization; or 2) is $POLKIT_USER; or 3) is group $POLKIT_USER
                 *
                 * 2. If so, resolves /prod/$pid/exe and writes it to stdout
                 */

                snprintf (buf, sizeof (buf), "%d", pid);

                if (!kit_spawn_sync (NULL,             /* const char  *working_directory */
                                     0,                /* flags */
                                     helper_argv,      /* char       **argv */
                                     NULL,             /* char       **envp */
                                     NULL,             /* char        *stdin */
                                     &standard_output, /* char       **stdout */
                                     NULL,             /* char       **stderr */
                                     &exit_status)) {  /* int         *exit_status */
                        goto out;
                }
                
                if (!WIFEXITED (exit_status)) {
                        kit_warning ("resolve exe helper crashed!");
                        goto out;
                } else if (WEXITSTATUS(exit_status) != 0) {
                        goto out;
                }

                strncpy (out_buf, standard_output, buf_size);
                out_buf[buf_size - 1] = '\0';
                ret = strlen (standard_output);
        }

out:
        return ret;
}


#ifdef HAVE_SOLARIS
int
polkit_sysdeps_pid_psinfo (pid_t pid, struct psinfo *ps)
{
        char pname[32];
        int  procfd;

        (void) snprintf(pname, sizeof(pname), "/proc/%d/psinfo", pid);
        if ((procfd = open(pname, O_RDONLY)) == -1) {
                return -1;
        }
        if (read(procfd, ps, sizeof(struct psinfo)) < 0) {
                (void) close(procfd);
                return -1;
        }
        (void) close(procfd);
        return 0;
}
#endif

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_sysdeps = {
        "polkit_sysdeps",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

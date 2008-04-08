/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-resolve-exe-helper.c : setuid root helper for PolicyKit to
 * resolve /proc/$pid/exe symlinks
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

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <utime.h>
#include <fcntl.h>
#include <dirent.h>

#include <polkit-dbus/polkit-dbus.h>
#include <polkit/polkit-private.h>

#ifdef HAVE_SOLARIS
#define LOG_AUTHPRIV	(10<<3)
#define PATH_MAX	1024
#endif

int
main (int argc, char *argv[])
{
        int ret;
        uid_t caller_uid;
        pid_t requesting_info_for_pid;
        char *endp;
        uid_t uid_for_polkit_user;
        struct passwd *pw;
        gid_t egid;
        struct group *group;
        int n;
        char buf[PATH_MAX];
        polkit_bool_t is_setgid_polkit;

        ret = 1;

        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
#ifdef HAVE_SOLARIS
	extern char **environ;

	if (environ != NULL)
		environ[0] = NULL;
#else
        if (clearenv () != 0)
                goto out;
#endif
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        openlog ("polkit-resolve-exe-helper", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (argc != 2) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-resolve-exe-helper: wrong number of arguments. This incident has been logged.\n");
                goto out;
        }

        caller_uid = getuid ();

        /* check we're running with a non-tty stdin */
        if (isatty (STDIN_FILENO) != 0) {
                syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                fprintf (stderr, "polkit-resolve-exe-helper: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                goto out;
        }

        pw = getpwnam (POLKIT_USER);
        if (pw == NULL) {
                fprintf (stderr, "polkit-resolve-exe-helper: cannot lookup uid for " POLKIT_USER "\n");
                goto out;
        }
        uid_for_polkit_user = pw->pw_uid;

        /* check if we are setgid polkituser */
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "polkit-resolve-exe-helper: cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) == 0) {
                is_setgid_polkit = TRUE;
        } else {
                is_setgid_polkit = FALSE;
        }

        /*----------------------------------------------------------------------------------------------------*/

        requesting_info_for_pid = strtoul (argv[1], &endp, 10);
        if (strlen (argv[1]) == 0 || *endp != '\0') {
                fprintf (stderr, "polkit-resolve-exe-helper: requesting_info_for_pid malformed\n");
                goto out;
        }

        /* user polkituser is allowed to resolve anything. So is any program that is setgid polkituser. */
        if (caller_uid != uid_for_polkit_user && !is_setgid_polkit) {
                pid_t ppid;
                        
                ppid = getppid ();
                if (ppid == 1)
                        goto out;

                /* need to set the real uid of the process to root ... otherwise D-Bus won't work */
                if (setuid (0) != 0) {
                        fprintf (stderr, "polkit-resolve-exe-helper: cannot do setuid(0): %m\n");
                        goto out;
                }

                if (polkit_check_auth (ppid, 
                                       "org.freedesktop.policykit.read", NULL) == 0) {
                        fprintf (stderr, "polkit-resolve-exe-helper: not authorized for org.freedesktop.policykit.read\n");
                        goto out;
                }
        }

        n = polkit_sysdeps_get_exe_for_pid (requesting_info_for_pid, buf, sizeof (buf));
        if (n == -1 || n >= (int) sizeof (buf)) {
                fprintf (stderr, "polkit-resolve-exe-helper: Cannot resolve link for pid %d\n", 
                         requesting_info_for_pid);
                goto out;
        }

        printf ("%s", buf);

        ret = 0;

out:
        return ret;
}


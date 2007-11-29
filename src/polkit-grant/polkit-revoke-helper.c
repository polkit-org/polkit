/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-revoke-helper.c : setgid polkituser revoke helper for PolicyKit
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
#include <sys/time.h>
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

#include <polkit-dbus/polkit-dbus.h>
#include <polkit/polkit-private.h>

static int
_write_to_fd (int fd, const char *str, ssize_t str_len)
{
        int ret;
        ssize_t written;

        ret = 0;

        written = 0;
        while (written < str_len) {
                ssize_t ret;
                ret = write (fd, str + written, str_len - written);
                if (ret < 0) {
                        if (errno == EAGAIN || errno == EINTR) {
                                continue;
                        } else {
                                goto out;
                        }
                }
                written += ret;
        }

        ret = 1;

out:
        return ret;
}

int
main (int argc, char *argv[])
{
        int ret;
        gid_t egid;
        struct group *group;
        uid_t invoking_uid;
        char *entry_to_remove;
        char *scope;
        uid_t uid_to_revoke;
        char *endp;
        FILE *f;
        int fd;
        char path[256];
        char path_tmp[256];
        char line[512];
        char *root;
        char *target_type;
        char *target_value;
        struct passwd *pw;
        polkit_bool_t is_one_shot;
        polkit_bool_t not_granted_by_self;
        char **tokens;
        size_t num_tokens;

        ret = 1;

#ifndef POLKIT_BUILD_TESTS
        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (clearenv () != 0)
                goto out;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
#endif

        openlog ("polkit-revoke-helper", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (argc != 4) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-revoke-helper: wrong number of arguments. This incident has been logged.\n");
                goto out;
        }

        /* check we're running with a non-tty stdin */
        if (isatty (STDIN_FILENO) != 0) {
                syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                fprintf (stderr, "polkit-revoke-helper: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                goto out;
        }

        invoking_uid = getuid ();

        /* check that we are setgid polkituser */
#ifdef POLKIT_BUILD_TESTS
        char *pretend;
        if ((pretend = getenv ("POLKIT_TEST_PRETEND_TO_BE_UID")) != NULL) {
                invoking_uid = atoi (pretend);
                goto skip_check;
        }
        kit_warning ("foo %s", pretend);
#endif
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "polkit-revoke-helper: cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) != 0) {
                fprintf (stderr, "polkit-revoke-helper: needs to be setgid " POLKIT_GROUP "\n");
                goto out;
        }
#ifdef POLKIT_BUILD_TESTS
skip_check:
#endif

        entry_to_remove = argv[1];
        target_type = argv[2];
        target_value = argv[3];

        /*----------------------------------------------------------------------------------------------------*/

        /* paranoia: we have to validate the entry_to_remove argument
         * and determine if the process who invoked us is sufficiently
         * privileged. 
         *
         * As we're setuid root we don't want to pull in libpolkit and
         * as we only need to parse the first two entries... we do it
         * right here
         */

        tokens = kit_strsplit (entry_to_remove, ':', &num_tokens);
        if (tokens == NULL || num_tokens < 2) {
                fprintf (stderr, "polkit-revoke-helper: entry_to_remove malformed\n");
                goto out;
        }

        scope = tokens[0];

        if (strcmp (target_type, "uid") == 0) {
                uid_to_revoke = strtol (target_value, &endp, 10);
                if  (*endp != '\0') {
                        fprintf (stderr, "polkit-revoke-helper: cannot parse uid\n");
                        goto out;
                }
        } else {
                fprintf (stderr, "polkit-revoke-helper: unknown target type\n");
                goto out;
        }

        /* OK, we're done parsing ... */

        not_granted_by_self = FALSE;

#ifdef POLKIT_BUILD_TESTS
        char *test_dir;
        char dir_run[256];
        char dir_lib[256];

        if ((test_dir = getenv ("POLKIT_TEST_LOCALSTATE_DIR")) == NULL) {
                test_dir = PACKAGE_LOCALSTATE_DIR;
        }
        kit_assert ((size_t) snprintf (dir_run, sizeof (dir_run), "%s/run/PolicyKit", test_dir) < sizeof (dir_run));
        kit_assert ((size_t) snprintf (dir_lib, sizeof (dir_lib), "%s/lib/PolicyKit", test_dir) < sizeof (dir_lib));

#else
        char *dir_run = PACKAGE_LOCALSTATE_DIR "/run/PolicyKit";
        char *dir_lib = PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit";
#endif


        is_one_shot = FALSE;
        if (strcmp (scope, "scope=process") == 0) {
                root = dir_run;
        } else if (strcmp (scope, "scope=process-one-shot") == 0) {
                root = dir_run;
                is_one_shot = TRUE;
        } else if (strcmp (scope, "scope=session") == 0) {
                root = dir_run;
        } else if (strcmp (scope, "scope=always") == 0) {
                root = dir_lib;
        } else if (strcmp (scope, "scope=grant") == 0 ||
                   strcmp (scope, "scope=grant-negative") == 0) {
                unsigned int n;

                root = dir_lib;

                for (n = 1; n < num_tokens; n++) {
                        if (strncmp (tokens[n], "granted-by=", sizeof ("granted-by=") - 1) == 0) {
                                uid_t granted_by;
                                granted_by = strtol (tokens[n] + sizeof ("granted-by=") - 1, &endp, 10);
                                if  (*endp != '\0') {
                                        fprintf (stderr, "polkit-revoke-helper: cannot parse granted-by uid\n");
                                        goto out;
                                }
                                
                                if (granted_by != invoking_uid)
                                        not_granted_by_self = TRUE;

                                goto parsed_granted_by;
                        }
                }

                fprintf (stderr, "polkit-revoke-helper: cannot find key granted-by\n");

                goto out;
        parsed_granted_by:
                ;
        } else {
                fprintf (stderr, "polkit-revoke-helper: unknown scope '%s'\n", scope);
                goto out;
        }


        if (invoking_uid != 0) {
                /* Check that the caller is privileged to do this... basically, callers can only
                 * revoke auths granted by themselves...
                 */
                if (not_granted_by_self) {
                        pid_t ppid;
                        
                        ppid = getppid ();
                        if (ppid == 1)
                                goto out;

                        if (polkit_check_auth (ppid, "org.freedesktop.policykit.revoke", NULL) == 0) {
                                goto out;
                        }
                }
        }

        pw = kit_getpwuid (uid_to_revoke);
        if (pw == NULL) {
                fprintf (stderr, "polkit-revoke-helper: cannot lookup user name for uid %d\n", uid_to_revoke);
                goto out;
        }

        if (snprintf (path, sizeof (path), "%s/user-%s.auths", root, pw->pw_name) >= (int) sizeof (path)) {
                fprintf (stderr, "polkit-revoke-helper: string was truncated (1)\n");
                goto out;
        }
        if (snprintf (path_tmp, sizeof (path_tmp), "%s/user-%s.auths.XXXXXX", root, pw->pw_name) >= (int) sizeof (path)) {
                fprintf (stderr, "polkit-revoke-helper: string was truncated (2)\n");
                goto out;
        }

        f = fopen (path, "r");
        if (f == NULL) {
                fprintf (stderr, "Cannot open file '%s': %m\n", path);
                goto out;
        }

        fd = mkstemp (path_tmp);
        if (fd < 0) {
                fprintf (stderr, "Cannot create file '%s': %m\n", path_tmp);
                goto out;
        }
        if (fchmod (fd, 0464) != 0) {
                fprintf (stderr, "Cannot change mode for '%s' to 0460: %m\n", path_tmp);
                close (fd);
                unlink (path_tmp);
                goto out;
        }


        /* read one line at a time */
        while (fgets (line, sizeof (line), f) != NULL) {
                size_t line_len;

                line_len = strlen (line);
                if (line_len > 1 && line[line_len - 1] == '\n') {
                        if (strncmp (line, entry_to_remove, line_len - 1) == 0) {
                                /* woho, found it */
                                continue;
                        }
                }

                /* otherwise, just write the line to the temporary file */
                if (!_write_to_fd (fd, line, line_len)) {
                        fprintf (stderr, "Error write to file '%s': %m\n", path_tmp);
                        close (fd);
                        unlink (path_tmp);
                        goto out;
                }
        }
        
        fclose (f);
        close (fd);

        if (rename (path_tmp, path) != 0) {
                fprintf (stderr, "Error renaming %s to %s: %m\n", path_tmp, path);
                unlink (path_tmp);
                goto out;
        }

        /* we're good now (if triggering a reload fails, so be it, we
         * still did what the caller asked...)
         */
        ret = 0;

#ifdef POLKIT_BUILD_TESTS
        if (test_dir != NULL)
                goto no_reload;
#endif
        /* trigger a reload */
        if (utimes (PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload", NULL) != 0) {
                fprintf (stderr, "Error updating access+modification time on file '%s': %m\n", 
                         PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload");
        }
#ifdef POLKIT_BUILD_TESTS
no_reload:
#endif

out:

        return ret;
}


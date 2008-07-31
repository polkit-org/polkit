/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-set-default-helper.c : setgid polkituser helper for PolicyKit
 * to set defaults
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
#include <sys/time.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <utime.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>

#include <polkit/polkit.h>
#include <polkit/polkit-private.h>

#ifdef HAVE_SOLARIS
#define LOG_AUTHPRIV    (10<<3)
#endif

static polkit_bool_t
set_default (const char *action_id, const char *any, const char *inactive, const char *active)
{
        char *path;
        char *contents;
        polkit_bool_t ret;

        path = NULL;
        contents = NULL;
        ret = FALSE;

        path = kit_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/polkit-public-1/%s.defaults-override", action_id);
        if (path == NULL)
                goto out;

        contents = kit_strdup_printf ("%s:%s:%s",
                                      any, inactive, active);
        if (contents == NULL)
                goto out;

        if (!kit_file_set_contents (path, 0644, contents, strlen (contents))) {
                kit_warning ("Error writing override file '%s': %m\n", path);
                goto out;
        }

        ret = TRUE;

out:
        if (path == NULL)
                kit_free (path);
        if (contents == NULL)
                kit_free (contents);
        return ret;
}

static polkit_bool_t
clear_default (const char *action_id)
{
        char *path;
        polkit_bool_t ret;

        ret = FALSE;

        path = kit_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/polkit-public-1/%s.defaults-override", action_id);
        if (path == NULL)
                goto out;

        if (unlink (path) != 0) {
                kit_warning ("Error unlinking file %s: %m", path);
        }

        ret = TRUE;

out:
        if (path == NULL)
                kit_free (path);
        return ret;

}

int
main (int argc, char *argv[])
{
        int ret;
        uid_t caller_uid;
        uid_t euid;
        struct passwd *pw;

        ret = 1;
        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (kit_clearenv () != 0)
                goto out;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        openlog ("polkit-set-default-helper-1", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (! (argc == 3 || argc == 6)) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-set-default-helper: wrong number of arguments. This incident has been logged.\n");
                goto out;
        }

        caller_uid = getuid ();

        /* check we're running with a non-tty stdin */
        if (isatty (STDIN_FILENO) != 0) {
                syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                fprintf (stderr, "polkit-set-default-helper: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                goto out;
        }

        /* check that we are setuid polkituser */
        euid = geteuid ();
        pw = getpwuid (euid);
        if (pw == NULL) {
                fprintf (stderr, "polkit-set-default-helper: cannot lookup passwd info for uid %d\n", euid);
                goto out;
        }
        if (strcmp (pw->pw_name, POLKIT_USER) != 0) {
                fprintf (stderr, "polkit-set-default-helper: needs to be setuid " POLKIT_USER "\n");
                goto out;
        }

        /*----------------------------------------------------------------------------------------------------*/

        /* uid 0 is allowed to set anything */
        if (caller_uid != 0) {
                pid_t ppid;
                        
                ppid = getppid ();
                if (ppid == 1)
                        goto out;

                if (polkit_check_auth (ppid, "org.freedesktop.policykit.modify-defaults", NULL) == 0) {
                        goto out;
                }
        }

        PolKitResult any;
        PolKitResult inactive;
        PolKitResult active;

        if (!polkit_action_validate_id (argv[1])) {
                goto out;
        }

        /* sanity check */
        if (argc == 3) {
                if (strcmp (argv[2], "clear") != 0)
                        goto out;

                if (!clear_default (argv[1]))
                        goto out;
        } else if (argc == 6) {
                if (strcmp (argv[2], "set") != 0)
                        goto out;

                if (!polkit_result_from_string_representation (argv[3], &any)) {
                        goto out;
                }
                if (!polkit_result_from_string_representation (argv[4], &inactive)) {
                        goto out;
                }
                if (!polkit_result_from_string_representation (argv[5], &active)) {
                        goto out;
                }
                
                if (!set_default (argv[1], argv[3], argv[4], argv[5]))
                        goto out;
        } else {
                goto out;
        }

        /* trigger a reload */
        if (utimes (PACKAGE_LOCALSTATE_DIR "/lib/misc/polkit-1.reload", NULL) != 0) {
                kit_warning ("Error updating access+modification time on file '%s': %m\n", 
                             PACKAGE_LOCALSTATE_DIR "/lib/misc/polkit-1.reload");
        }

        ret = 0;

out:
        return ret;
}


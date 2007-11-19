/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-set-default-helper.c : setgid polkituser helper for PolicyKit
 * to set defaults
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
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
#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <utime.h>
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>

#include <polkit/polkit-private.h>
#include <polkit-dbus/polkit-dbus.h>

static polkit_bool_t
set_default (const char *action_id, const char *any, const char *inactive, const char *active)
{
        char *path;
        char *contents;
        polkit_bool_t ret;

        path = NULL;
        contents = NULL;
        ret = FALSE;

        path = kit_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit-public/%s.override", action_id);
        if (path == NULL)
                goto out;

        contents = kit_strdup_printf ("%s:%s:%s",
                                      any, inactive, active);
        if (contents == NULL)
                goto out;

        if (!kit_file_set_contents (path, 0464, contents, strlen (contents))) {
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

        path = kit_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit-public/%s.override", action_id);
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
        gid_t egid;
        struct group *group;
        uid_t caller_uid;
        struct passwd *pw;
        uid_t uid_for_polkit_user;

        ret = 1;
        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (clearenv () != 0)
                goto out;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        openlog ("polkit-set-default-helper", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

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

        /* check that we are setgid polkituser */
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "polkit-set-default-helper: cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) != 0) {
                fprintf (stderr, "polkit-set-default-helper: needs to be setgid " POLKIT_GROUP "\n");
                goto out;
        }

        pw = getpwnam (POLKIT_USER);
        if (pw == NULL) {
                fprintf (stderr, "polkit-set-default-helper: cannot lookup uid for " POLKIT_USER "\n");
                goto out;
        }
        uid_for_polkit_user = pw->pw_uid;

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
        if (utimes (PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload", NULL) != 0) {
                kit_warning ("Error updating access+modification time on file '%s': %m\n", 
                             PACKAGE_LOCALSTATE_DIR "/lib/misc/PolicyKit.reload");
        }

        ret = 0;

out:
        return ret;
}


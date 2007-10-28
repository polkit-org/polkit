/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-read-auth-helper.c : setgid polkituser helper for PolicyKit
 * to read authorizations
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

/* This is a bit incestuous; we are, effectively, calling into
 * ourselves.. it's safe though; this function will never get hit..
 */
static polkit_bool_t
check_for_auth (uid_t caller_uid, pid_t caller_pid)
{
        polkit_bool_t ret;
        DBusError error;
        DBusConnection *bus;
        PolKitCaller *caller;
        PolKitAction *action;
        PolKitContext *context;

        ret = FALSE;

        dbus_error_init (&error);
        bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot connect to system bus: %s: %s\n", 
                         error.name, error.message);
                dbus_error_free (&error);
                goto out;
        }

        caller = polkit_caller_new_from_pid (bus, caller_pid, &error);
        if (caller == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot get caller from pid: %s: %s\n",
                         error.name, error.message);
                goto out;
        }

        action = polkit_action_new ();
        if (action == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot allocate PolKitAction\n");
                goto out;
        }
        if (!polkit_action_set_action_id (action, "org.freedesktop.policykit.read")) {
                fprintf (stderr, "polkit-read-auth-helper: cannot set action_id\n");
                goto out;
        }

        context = polkit_context_new ();
        if (context == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot allocate PolKitContext\n");
                goto out;
        }
        if (!polkit_context_init (context, NULL)) {
                fprintf (stderr, "polkit-read-auth-helper: cannot initialize polkit\n");
                goto out;
        }

        if (polkit_context_is_caller_authorized (context, action, caller, FALSE) != POLKIT_RESULT_YES) {
                /* having 'grant' (which is a lot more powerful) is also sufficient.. this is because 'read'
                 * is required to 'grant' (to check if there's a similar authorization already)
                 */
                if (!polkit_action_set_action_id (action, "org.freedesktop.policykit.grant")) {
                        fprintf (stderr, "polkit-read-auth-helper: cannot set action_id\n");
                        goto out;
                }
                if (polkit_context_is_caller_authorized (context, action, caller, FALSE) != POLKIT_RESULT_YES) {
                        goto out;
                }
        }

        ret = TRUE;
out:

        return ret;
}

static polkit_bool_t
dump_auths_from_file (const char *path)
{
        int ret;
        int fd;
        char buf[256];
        struct stat statbuf;
        ssize_t num_bytes_read;
        ssize_t num_bytes_to_read;
        ssize_t num_bytes_remaining_to_read;
        ssize_t num_bytes_to_write;
        ssize_t num_bytes_written;
        ssize_t num_bytes_remaining_to_write;

        ret = FALSE;

        if (stat (path, &statbuf) != 0) {
                /* this is fine; the file does not have to exist.. */
                if (errno == ENOENT) {
                        ret = TRUE;
                        goto out;
                }
                fprintf (stderr, "polkit-read-auth-helper: cannot stat %s: %m\n", path);
                goto out;
        }

        fd = open (path, O_RDONLY);
        if (fd < 0) {
                fprintf (stderr, "polkit-read-auth-helper: cannot open %s: %m\n", path);
                goto out;
        }

        num_bytes_remaining_to_read = statbuf.st_size;

        while (num_bytes_remaining_to_read > 0) {
                if (num_bytes_remaining_to_read > (ssize_t) sizeof (buf))
                        num_bytes_to_read = (ssize_t) sizeof (buf);
                else
                        num_bytes_to_read = num_bytes_remaining_to_read;
                
        again:
                num_bytes_read = read (fd, buf, num_bytes_to_read);
                if (num_bytes_read == -1) {
                        if (errno == EAGAIN || errno == EINTR) {
                                goto again;
                        } else {
                                fprintf (stderr, "polkit-read-auth-helper: error reading file %s: %m\n", path);
                                close (fd);
                                goto out;
                        }
                }

                /* write to stdout */
                num_bytes_to_write = num_bytes_read;
                num_bytes_remaining_to_write = num_bytes_read;

                while (num_bytes_remaining_to_write > 0) {
                again_write:
                        num_bytes_written = write (STDOUT_FILENO, 
                                                   buf + (num_bytes_to_write - num_bytes_remaining_to_write), 
                                                   num_bytes_remaining_to_write);
                        if (num_bytes_written == -1) {
                                if (errno == EAGAIN || errno == EINTR) {
                                        goto again_write;
                                } else {
                                        fprintf (stderr, "polkit-read-auth-helper: error writing to stdout: %m\n");
                                        close (fd);
                                        goto out;
                                }
                        }
                        
                        num_bytes_remaining_to_write -= num_bytes_written;
                }

                
                


                num_bytes_remaining_to_read -= num_bytes_read;
        }


        close (fd);

        ret = TRUE;

out:
        return ret;
}

static polkit_bool_t
dump_auths_all (const char *root)
{
        DIR *dir;
        int dfd;
        struct dirent64 *d;
        polkit_bool_t ret;

        ret = FALSE;

        dir = opendir (root);
        if (dir == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: error calling opendir on %s: %m\n", root);
                goto out;
        }

        dfd = dirfd (dir);
        if (dfd == -1) {
                fprintf (stderr, "polkit-read-auth-helper: error calling dirfd(): %m\n");
                goto out;
        }

        while ((d = readdir64(dir)) != NULL) {
                size_t name_len;
                char path[PATH_MAX];
                static const char suffix[] = ".auths";

                if (d->d_type != DT_REG)
                        continue;

                if (d->d_name == NULL)
                        continue;

                name_len = strlen (d->d_name);
                if (name_len < sizeof (suffix))
                        continue;

                if (strcmp ((d->d_name + name_len - sizeof (suffix) + 1), suffix) != 0)
                        continue;

                if (snprintf (path, sizeof (path), "%s/%s", root, d->d_name) >= (int) sizeof (path)) {
                        fprintf (stderr, "polkit-read-auth-helper: string was truncated (1)\n");
                        goto out;
                }

                if (!dump_auths_from_file (path))
                        goto out;
        }

        ret = TRUE;

out:
        if (dir != NULL)
                closedir(dir);
        return ret;
}

static polkit_bool_t
dump_auths_for_uid (const char *root, uid_t uid)
{
        char path[256];
        struct passwd *pw;

        pw = getpwuid (uid);
        if (pw == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot lookup user name for uid %d\n", uid);
                return FALSE;
        }

        if (snprintf (path, sizeof (path), "%s/user-%s.auths", root, pw->pw_name) >= (int) sizeof (path)) {
                fprintf (stderr, "polkit-read-auth-helper: string was truncated (1)\n");
                return FALSE;
        }

        return dump_auths_from_file (path);
}


int
main (int argc, char *argv[])
{
        int ret;
        gid_t egid;
        struct group *group;
        uid_t caller_uid;
        uid_t requesting_info_for_uid;
        char *endp;

        ret = 1;
        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        //if (clearenv () != 0)
        //        goto out;
        /* set a minimal environment */
        //setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        openlog ("polkit-read-auth-helper", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (argc != 2) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-read-auth-helper: wrong number of arguments. This incident has been logged.\n");
                goto out;
        }

        caller_uid = getuid ();

        /* check we're running with a non-tty stdin */
        if (isatty (STDIN_FILENO) != 0) {
                syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                fprintf (stderr, "polkit-read-auth-helper: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                goto out;
        }
        
        /* check that we are setgid polkituser */
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) != 0) {
                fprintf (stderr, "polkit-read-auth-helper: needs to be setgid " POLKIT_GROUP "\n");
                goto out;
        }

        /*----------------------------------------------------------------------------------------------------*/

        requesting_info_for_uid = strtoul (argv[1], &endp, 10);
        if  (*endp != '\0') {
                fprintf (stderr, "polkit-read-auth-helper: requesting_info_for_uid malformed (3)\n");
                goto out;
        }

        /* uid 0 is allowed to read anything */
        if (caller_uid != 0) {
                if (caller_uid != requesting_info_for_uid) {

                        /* see if calling user has the
                         *
                         *  org.freedesktop.policykit.read
                         *
                         * authorization
                         */
                        if (!check_for_auth (caller_uid, getppid ())) {
                                //fprintf (stderr, 
                                //         "polkit-read-auth-helper: uid %d cannot read authorizations for uid %d.\n", 
                                //        caller_uid,
                                //        requesting_info_for_uid);
                                goto out;
                        }
                }
        }

        if (requesting_info_for_uid == (uid_t) -1) {
                if (!dump_auths_all (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit"))
                        goto out;
                
                if (!dump_auths_all (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit"))
                        goto out;                
        } else {
                if (!dump_auths_for_uid (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit", requesting_info_for_uid))
                        goto out;
                
                if (!dump_auths_for_uid (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit", requesting_info_for_uid))
                        goto out;
        }

        ret = 0;

out:
        return ret;
}


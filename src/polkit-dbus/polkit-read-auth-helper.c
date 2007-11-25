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
#include <polkit/polkit-private.h>

static polkit_bool_t
dump_auths_from_file (const char *path, uid_t uid)
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
        polkit_bool_t have_written_uid;

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

        have_written_uid = FALSE;
        while (num_bytes_remaining_to_read > 0) {

                /* start with writing the uid - this is necessary when dumping all authorizations via uid=1 */
                if (!have_written_uid) {
                        have_written_uid = TRUE;
                        snprintf (buf, sizeof (buf), "#uid=%d\n", uid);
                        num_bytes_read = strlen (buf);
                } else {

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

                        num_bytes_remaining_to_read -= num_bytes_read;
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

        }


        close (fd);

        ret = TRUE;

out:
        return ret;
}

#ifdef POLKIT_BUILD_TESTS
static struct passwd *
kit_getpwnam (const char *username)
{
        struct passwd *pw;
        FILE *f;
        const char *passwd_file;

        f = NULL;
        pw = NULL;

        if ((passwd_file = getenv ("POLKIT_TEST_PASSWD_FILE")) == NULL)
                return getpwnam (username);

        f = fopen (passwd_file, "r");
        if (f == NULL)
                goto out;

        while ((pw = fgetpwent (f)) != NULL) {
                if (strcmp (pw->pw_name, username) == 0)
                        goto out;
        }

out:
        if (f != NULL)
                fclose (f);
        return pw;
}

static struct passwd *
kit_getpwuid (uid_t uid)
{
        struct passwd *pw;
        FILE *f;
        const char *passwd_file;

        f = NULL;
        pw = NULL;

        if ((passwd_file = getenv ("POLKIT_TEST_PASSWD_FILE")) == NULL)
                return getpwuid (uid);

        f = fopen (passwd_file, "r");
        if (f == NULL)
                goto out;

        while ((pw = fgetpwent (f)) != NULL) {
                if (pw->pw_uid == uid)
                        goto out;
        }

out:
        if (f != NULL)
                fclose (f);
        return pw;
}
#else
static struct passwd *
kit_getpwnam (const char *username)
{
        return getpwnam (username);
}

static struct passwd *
kit_getpwuid (uid_t uid)
{
        return getpwuid (uid);
}
#endif

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
                unsigned int n, m;
                uid_t uid;
                size_t name_len;
                char *filename;
                char username[PATH_MAX];
                char path[PATH_MAX];
                static const char suffix[] = ".auths";
                struct passwd *pw;

                if (d->d_type != DT_REG)
                        continue;

                if (d->d_name == NULL)
                        continue;

                filename = d->d_name;
                name_len = strlen (filename);
                if (name_len < sizeof (suffix))
                        continue;

                if (strcmp ((filename + name_len - sizeof (suffix) + 1), suffix) != 0)
                        continue;

                /* find the user name.. */
                for (n = 0; n < name_len; n++) {
                        if (filename[n] == '-')
                                break;
                }
                if (filename[n] == '\0') {
                        fprintf (stderr, "polkit-read-auth-helper: file name '%s' is malformed (1)\n", filename);
                        continue;
                }
                n++;
                m = n;
                for ( ; n < name_len; n++) {
                        if (filename[n] == '.')
                                break;
                }

                if (filename[n] == '\0') {
                        fprintf (stderr, "polkit-read-auth-helper: file name '%s' is malformed (2)\n", filename);
                        continue;
                }
                if (n - m > sizeof (username) - 1) {
                        fprintf (stderr, "polkit-read-auth-helper: file name '%s' is malformed (3)\n", filename);
                        continue;
                }
                strncpy (username, filename + m, n - m);
                username[n - m] = '\0';

                pw = kit_getpwnam (username);
                if (pw == NULL) {
                        fprintf (stderr, "polkit-read-auth-helper: cannot look up uid for username %s\n", username);
                        continue;
                }
                uid = pw->pw_uid;
                
                if (snprintf (path, sizeof (path), "%s/%s", root, filename) >= (int) sizeof (path)) {
                        fprintf (stderr, "polkit-read-auth-helper: string was truncated (1)\n");
                        goto out;
                }

                if (!dump_auths_from_file (path, uid))
                        goto out;
        }

        ret = TRUE;

out:
        if (dir != NULL)
                closedir (dir);
        return ret;
}

static polkit_bool_t
dump_auths_for_uid (const char *root, uid_t uid)
{
        char path[256];
        struct passwd *pw;

        pw = kit_getpwuid (uid);
        if (pw == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot lookup user name for uid %d\n", uid);
                return FALSE;
        }

        if (snprintf (path, sizeof (path), "%s/user-%s.auths", root, pw->pw_name) >= (int) sizeof (path)) {
                fprintf (stderr, "polkit-read-auth-helper: string was truncated (1)\n");
                return FALSE;
        }

        return dump_auths_from_file (path, uid);
}


int
main (int argc, char *argv[])
{
        int ret;
        uid_t caller_uid;
        uid_t requesting_info_for_uid;
        char *endp;
        uid_t uid_for_polkit_user;

        ret = 1;

#ifndef POLKIT_BUILD_TESTS
        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (clearenv () != 0)
                goto out;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
#endif

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

#ifdef POLKIT_BUILD_TESTS
        char *pretend;
        if ((pretend = getenv ("POLKIT_TEST_PRETEND_TO_BE_UID")) != NULL) {
                caller_uid = atoi (pretend);
                goto skip_check;
        }
#endif
        gid_t egid;
        struct group *group;
        struct passwd *pw;

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

#ifdef POLKIT_BUILD_TESTS
skip_check:
#endif

        pw = kit_getpwnam (POLKIT_USER);
        if (pw == NULL) {
                fprintf (stderr, "polkit-read-auth-helper: cannot lookup uid for " POLKIT_USER "\n");
                goto out;
        }
        uid_for_polkit_user = pw->pw_uid;

        /*----------------------------------------------------------------------------------------------------*/

        requesting_info_for_uid = strtoul (argv[1], &endp, 10);
        if  (*endp != '\0') {
                fprintf (stderr, "polkit-read-auth-helper: requesting_info_for_uid malformed (3)\n");
                goto out;
        }

        /* uid 0 and user polkituser is allowed to read anything */
        if (caller_uid != 0 && caller_uid != uid_for_polkit_user) {
                if (caller_uid != requesting_info_for_uid) {
                        pid_t ppid;
                        
                        ppid = getppid ();
                        if (ppid == 1)
                                goto out;

                        if (polkit_check_auth (ppid, 
                                               "org.freedesktop.policykit.read", 
                                               "org.freedesktop.policykit.grant", NULL) == 0) {
                                goto out;
                        }
                }
        }

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

        if (requesting_info_for_uid == (uid_t) -1) {
                if (!dump_auths_all (dir_run))
                        goto out;
                
                if (!dump_auths_all (dir_lib))
                        goto out;                
        } else {
                if (!dump_auths_for_uid (dir_run, requesting_info_for_uid))
                        goto out;
                
                if (!dump_auths_for_uid (dir_lib, requesting_info_for_uid))
                        goto out;
        }

        ret = 0;

out:
        return ret;
}


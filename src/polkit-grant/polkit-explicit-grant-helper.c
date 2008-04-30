/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-explicit-grant-helper.c : setgid polkituser explicit grant
 * helper for PolicyKit
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
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <utime.h>
#include <fcntl.h>

#include <polkit-dbus/polkit-dbus.h>
#include <polkit/polkit-private.h>

#ifdef HAVE_SOLARIS
#define LOG_AUTHPRIV    (10<<3)
#endif

int
main (int argc, char *argv[])
{
        int ret;
        gid_t egid;
        struct group *group;
        uid_t invoking_uid;
        char *action_id;
        char *endp;
        struct timeval now;

        ret = 1;

        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (kit_clearenv () != 0)
                goto out;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        openlog ("polkit-explicit-grant-helper", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (argc != 5) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-explicit-grant-helper: wrong number of arguments. This incident has been logged.\n");
                goto out;
        }

        /* check we're running with a non-tty stdin */
        if (isatty (STDIN_FILENO) != 0) {
                syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                fprintf (stderr, "polkit-explicit-grant-helper: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                goto out;
        }

        invoking_uid = getuid ();

        /* check that we are setgid polkituser */
        egid = getegid ();
        group = getgrgid (egid);
        if (group == NULL) {
                fprintf (stderr, "polkit-explicit-grant-helper: cannot lookup group info for gid %d\n", egid);
                goto out;
        }
        if (strcmp (group->gr_name, POLKIT_GROUP) != 0) {
                fprintf (stderr, "polkit-explicit-grant-helper: needs to be setgid " POLKIT_GROUP "\n");
                goto out;
        }

        /*----------------------------------------------------------------------------------------------------*/

        /* check and validate incoming parameters */

        /* first one is action_id */
        action_id = argv[1];
        if (!polkit_action_validate_id (action_id)) {
                syslog (LOG_NOTICE, "action_id is malformed [uid=%d]", getuid ());
                fprintf (stderr, "polkit-explicit-grant-helper: action_id is malformed. This incident has been logged.\n");
                goto out;
        }

        char *authc_str;
        size_t authc_str_len;

        /* second is the textual form of the auth constraint */
        authc_str = argv[2];
        authc_str_len = strlen (authc_str);

#define TARGET_UID 0
        int target;
        uid_t target_uid = -1;
        polkit_bool_t is_negative;

        is_negative = FALSE;

        /* (third, fourth) is one of: ("uid", uid), ("uid-negative", uid) */
        if (strcmp (argv[3], "uid") == 0 || strcmp (argv[3], "uid-negative") == 0) {

                if (strcmp (argv[3], "uid") != 0) {
                        is_negative = TRUE;
                }

                target = TARGET_UID;
                target_uid = strtol (argv[4], &endp, 10);
                if  (*endp != '\0') {
                        syslog (LOG_NOTICE, "target uid is malformed [uid=%d]", getuid ());
                        fprintf (stderr, "polkit-explicit-grant-helper: target uid is malformed. This incident has been logged.\n");
                        goto out;
                }
        } else {
                syslog (LOG_NOTICE, "target type is malformed [uid=%d]", getuid ());
                fprintf (stderr, "polkit-explicit-grant-helper: target type is malformed. This incident has been logged.\n");
                goto out;
        }


        //fprintf (stderr, "action_id=%s constraint=%s uid=%d\n", action_id, authc_str, target_uid);

        /* OK, we're done parsing ... check if the user is authorized */

        if (invoking_uid != 0) {

                if (is_negative && (invoking_uid == target_uid)) {
                        /* it's fine to grant negative-auths to one self... */
                } else {
                        pid_t ppid;
                        
                        ppid = getppid ();
                        if (ppid == 1)
                                goto out;
                        
                        if (polkit_check_auth (ppid, "org.freedesktop.policykit.grant", NULL) == 0) {
                                goto out;
                        }
                }
        }

        /* he is.. proceed to add the grant */

        umask (002);

        if (gettimeofday (&now, NULL) != 0) {
                fprintf (stderr, "polkit-explicit-grant-helper: error calling gettimeofday: %m");
                return FALSE;
        }

        char now_buf[32];
        char uid_buf[32];
        char auth_buf[1024];
        snprintf (now_buf, sizeof (now_buf), "%Lu", (polkit_uint64_t) now.tv_sec);
        snprintf (uid_buf, sizeof (uid_buf), "%d", invoking_uid);

        size_t len;
        if ((len = kit_string_entry_create (auth_buf, sizeof (auth_buf),
                                            "scope",          is_negative ? "grant-negative" : "grant",
                                            "action-id",      action_id,
                                            "when",           now_buf,
                                            "granted-by",     uid_buf,
                                            NULL)) >= sizeof (auth_buf)) {
                kit_warning ("polkit-explicit-grant-helper: authbuf is too small");
                goto out;
        }
        if (authc_str_len > 0) {
                if (sizeof (auth_buf) - len < authc_str_len + 1) {
                        kit_warning ("polkit-explicit-grant-helper: authbuf is too small");
                        goto out;
                }
                strncpy (auth_buf + len, authc_str, authc_str_len + 1);
        }

        if (_polkit_authorization_db_auth_file_add (FALSE, 
                                                    target_uid, 
                                                    auth_buf)) {
                ret = 0;
        }

out:

        return ret;
}


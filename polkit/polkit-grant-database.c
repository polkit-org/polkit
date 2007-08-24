/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant-database.c : simple interface for storing and checking grants
 * 
 * (This is an internal and private interface to PolicyKit. Do not use.)
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>

#include <polkit/polkit-grant-database.h>
#include <polkit/polkit-debug.h>

/**
 * SECTION:polkit-grant-database
 * @short_description: Local grant database
 *
 * This private class is used to represent the grant database and provides read/write functions to access it.
 **/

/* TODO FIXME: this is Linux specific */
static polkit_uint64_t 
get_start_time_for_pid (pid_t pid)
{
        char *filename;
        char *contents;
        gsize length;
        polkit_uint64_t start_time;
        GError *error = NULL;
        char **tokens;
        char *p;
        char *endp;

        start_time = 0;
        contents = NULL;

        filename = g_strdup_printf ("/proc/%d/stat", pid);
        if (filename == NULL) {
                fprintf (stderr, "Out of memory\n");
                goto out;
        }

        if (!g_file_get_contents (filename, &contents, &length, &error)) {
                fprintf (stderr, "Cannot get contents of '%s': %s\n", filename, error->message);
                g_error_free (error);
                goto out;
        }

        /* start time is the 19th token after the '(process name)' entry */

        p = strchr (contents, ')');
        if (p == NULL) {
                goto out;
        }
        p += 2; /* skip ') ' */
        if (p - contents >= (int) length) {
                goto out;
        }

        tokens = g_strsplit (p, " ", 0);
        if (g_strv_length (tokens) < 20) {
                goto out;
        }

        start_time = strtoll (tokens[19], &endp, 10);
        if (endp == tokens[19]) {
                goto out;
        }

        g_strfreev (tokens);

out:
        g_free (filename);
        g_free (contents);
        return start_time;
}

#if 0
static polkit_bool_t
ensure_dir (const char *file)
{
        char *dirname;
        polkit_bool_t ret;

        ret = FALSE;

        dirname = g_path_get_dirname (file);
        if (dirname == NULL)
                goto out;

        if (g_file_test (dirname, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)) {
                /* TODO: check permissions? */
                ret = TRUE;
                goto out;
        }

        if (mkdir (dirname, 0570) != 0) {
                fprintf (stderr, "Cannot create directory '%s': %s\n", dirname, strerror (errno));
                goto out;
        }

        ret = TRUE;

out:
        return ret;
}
#endif

static polkit_bool_t 
_polkit_grantdb_write (const char *grant_file)
{
        int fd;
        polkit_bool_t ret;

        ret = FALSE;

#if 0
        if (!ensure_dir (grant_file))
                goto out;
#endif

        fd = open (grant_file, O_CREAT | O_RDWR, 0460);
        if (fd < 0) {
                fprintf (stderr, "Cannot create file '%s': %s\n", grant_file, strerror (errno));
                goto out;
        }
        /* Yessir, the file is empty */
        close (fd);

        ret = TRUE;

out:
        return ret;
}

polkit_bool_t 
_polkit_grantdb_write_pid (const char *action_id, pid_t pid)
{
        char *grant_file;
        polkit_bool_t ret = FALSE;
        polkit_uint64_t pid_start_time;

        pid_start_time = get_start_time_for_pid (pid);
        if (pid_start_time == 0)
                goto out;

        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/uid%d-pid-%d@%Lu-%s.grant", 
                                      getuid(), pid, pid_start_time, action_id);
        if (grant_file == NULL) {
                fprintf (stderr, "Out of memory\n");
                goto out;
        }

        ret = _polkit_grantdb_write (grant_file);
out:
        return ret;
}

polkit_bool_t 
_polkit_grantdb_write_keep_session (const char *action_id, const char *session_id)
{
        char *grant_file;
        polkit_bool_t ret = FALSE;

        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/uid%d-session-%s-%s.grant", 
                                      getuid(), g_basename (session_id), action_id);
        if (grant_file == NULL) {
                fprintf (stderr, "Out of memory\n");
                goto out;
        }

        ret = _polkit_grantdb_write (grant_file);
out:
        return ret;
}

polkit_bool_t
_polkit_grantdb_write_keep_always (const char *action_id, uid_t uid)
{
        char *grant_file;
        polkit_bool_t ret = FALSE;

        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit/uid%d-%s.grant", 
                                      getuid(), action_id);
        if (grant_file == NULL) {
                fprintf (stderr, "Out of memory\n");
                goto out;
        }

        ret = _polkit_grantdb_write (grant_file);
out:
        return ret;
}

PolKitResult 
_polkit_grantdb_check_can_caller_do_action (PolKitContext         *pk_context,
                                            PolKitAction          *action,
                                            PolKitCaller          *caller)
{
        char *grant_file;
        PolKitResult result;
        char *action_id;
        uid_t invoking_user_id;
        pid_t invoking_process_id;
        PolKitSession *session;
        char *session_objpath;
        polkit_uint64_t pid_start_time;

        grant_file = NULL;
        result = POLKIT_RESULT_UNKNOWN;

        if (caller == NULL)
                goto out;

        if (!polkit_action_get_action_id (action, &action_id))
                goto out;

        if (!polkit_caller_get_uid (caller, &invoking_user_id))
                goto out;

        if (!polkit_caller_get_pid (caller, &invoking_process_id))
                goto out;

        session_objpath = NULL;
        if (polkit_caller_get_ck_session (caller, &session)) {
                if (!polkit_session_get_ck_objref (session, &session_objpath))
                        session_objpath = NULL;
        }

        pid_start_time = get_start_time_for_pid (invoking_process_id);
        if (pid_start_time == 0)
                goto out;

        /* first check what _write_pid may have left */
        grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/uid%d-pid-%d@%Lu-%s.grant", 
                                      invoking_user_id, invoking_process_id, pid_start_time, action_id);
        if (grant_file == NULL) {
                fprintf (stderr, "Out of memory\n");
                g_free (grant_file);
                goto out;
        }
        if (g_file_test (grant_file, G_FILE_TEST_EXISTS)) {
                result = POLKIT_RESULT_YES;
                g_free (grant_file);
                goto out;
        }
        g_free (grant_file);

        /* second, check what _keep_session may have left */
        if (session_objpath != NULL) {
                grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/uid%d-session-%s-%s.grant", 
                                              invoking_user_id, g_basename (session_objpath), action_id);
                if (grant_file == NULL) {
                        fprintf (stderr, "Out of memory\n");
                        g_free (grant_file);
                        goto out;
                }
                if (g_file_test (grant_file, G_FILE_TEST_EXISTS)) {
                        result = POLKIT_RESULT_YES;
                        g_free (grant_file);
                        goto out;
                }
                g_free (grant_file);
        }

        /* finally, check what _keep_always may have left */
        if (session_objpath != NULL) {
                grant_file = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit/uid%d-%s.grant", 
                                              invoking_user_id, action_id);
                if (grant_file == NULL) {
                        fprintf (stderr, "Out of memory\n");
                        g_free (grant_file);
                        goto out;
                }
                if (g_file_test (grant_file, G_FILE_TEST_EXISTS)) {
                        result = POLKIT_RESULT_YES;
                        g_free (grant_file);
                        goto out;
                }
                g_free (grant_file);
        }

out:
        return result;
}

void 
_polkit_grantdb_foreach (PolKitGrantDbForeachFunc callback, void *user_data)
{
        GDir *dir;
        const char *name;
        time_t when;

        g_return_if_fail (callback != NULL);

        _pk_debug ("Looking at run");
        dir = g_dir_open (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit", 0, NULL);
        if (dir != NULL) {
                while ((name = g_dir_read_name (dir)) != NULL) {
                        int uid;
                        char *endptr;
                        char *action;
                        char *path;
                        struct stat statbuf;

                        path = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/%s", name);
                        if (stat (path, &statbuf) != 0) {
                                g_free (path);
                                continue;
                        }
                        when = statbuf.st_mtime;
                        g_free (path);

                        if (!g_str_has_prefix (name, "uid"))
                                continue;
                        if (!g_str_has_suffix (name, ".grant"))
                                continue;

                        uid = strtol (name + 3 /* uid */, &endptr, 10);
                        if (endptr == NULL || *endptr != '-')
                                continue;

                        if (strncmp (endptr + 1, "pid-", 4) == 0) {
                                int pid;
                                polkit_uint64_t pid_time;

                                pid = strtol (endptr + 1 + 4 /*pid-*/, &endptr, 10);
                                if (endptr == NULL || *endptr != '@')
                                        continue;
                                pid_time = strtol (endptr + 1, NULL, 10);

                                while (*endptr != '-' && *endptr != '\0')
                                        endptr++;
                                if (*endptr == '\0')
                                        continue;
                                action = g_strdup (endptr + 1);
                                if (strlen (action) < 6) /* .grant */
                                        continue;
                                action[strlen(action) - 6] = '\0';

                                callback (action, uid, when, POLKIT_GRANTDB_GRANT_TYPE_PROCESS, 
                                          pid, pid_time, NULL, user_data);

                                g_free (action);
                        } else if (strncmp (endptr + 1, "session-", 8) == 0) {
                                int n;
                                char *session;

                                session = g_strdup (endptr + 1 + 8);
                                for (n = 0; session[n] != '-' && session[n] != '\0'; n++)
                                        ;
                                session[n] = '\0';

                                action = g_strdup (endptr + 1 + 8 + n + 1);
                                if (strlen (action) < 6) /* .grant */
                                        continue;
                                action[strlen(action) - 6] = '\0';

                                callback (action, uid, when, POLKIT_GRANTDB_GRANT_TYPE_SESSION, 
                                          (pid_t) -1, 0, session, user_data);

                                g_free (action);
                                g_free (session);
                        }


                }
                g_dir_close (dir);
        }

        _pk_debug ("Looking at lib");
        dir = g_dir_open (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit", 0, NULL);
        if (dir != NULL) {
                while ((name = g_dir_read_name (dir)) != NULL) {
                        int uid;
                        char *action;
                        char *endptr;
                        char *path;
                        struct stat statbuf;

                        path = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit/%s", name);
                        if (stat (path, &statbuf) != 0) {
                                g_free (path);
                                continue;
                        }
                        when = statbuf.st_mtime;
                        g_free (path);

                        if (!g_str_has_prefix (name, "uid"))
                                continue;
                        if (!g_str_has_suffix (name, ".grant"))
                                continue;

                        uid = strtol (name + 3 /* uid */, &endptr, 10);
                        if (endptr == NULL || *endptr != '-')
                                continue;
                        action = g_strdup (endptr + 1);
                        if (strlen (action) < 6) /* .grant */
                                continue;
                        action[strlen(action) - 6] = '\0';
                        
                        callback (action, uid, when, POLKIT_GRANTDB_GRANT_TYPE_ALWAYS, 
                                  (pid_t) -1, 0, NULL, user_data);

                        g_free (action);
                }
                g_dir_close (dir);
        }
}

polkit_bool_t
_polkit_grantdb_delete_for_user (uid_t uid)
{
        int n;
        GDir *dir;
        const char *name;
        polkit_bool_t ret;

        ret = FALSE;

        _pk_debug ("deleting grants for uid %d", uid);

        for (n = 0; n < 2; n++) {
                if (n == 0)
                        dir = g_dir_open (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit", 0, NULL);
                else
                        dir = g_dir_open (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit", 0, NULL);
                if (dir != NULL) {
                        while ((name = g_dir_read_name (dir)) != NULL) {
                                uid_t uid_in_grant;
                                char *endptr;
                                char *path;
                                
                                if (!g_str_has_prefix (name, "uid"))
                                        continue;
                                if (!g_str_has_suffix (name, ".grant"))
                                        continue;
                                
                                uid_in_grant = (uid_t) strtol (name + 3 /* uid */, &endptr, 10);
                                if (endptr == NULL || *endptr != '-')
                                        continue;
                                
                                if (uid_in_grant != uid)
                                        continue;
                                
                                if (n == 0)
                                        path = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/run/PolicyKit/%s", name);
                                else
                                        path = g_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit/%s", name);
                                if (unlink (path) != 0) {
                                        _pk_debug ("Error deleting grant file '%s': %s", path, strerror (errno));
                                        goto out;
                                }
                                _pk_debug ("Deleting file %s", path);
                                g_free (path);
                                
                        }
                        g_dir_close (dir);
                }
        }

        ret = TRUE;

out:
        return ret;
}

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-module-allow-all.c : PolicyKit module that says YES to everything
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>

#include <libpolkit/libpolkit-module.h>

/* The symbol that libpolkit looks up when loading this module */
gboolean libpolkit_module_set_functions (PolKitModuleInterface *module_interface);

typedef struct {
        regex_t preg;
        uid_t uid;
        gboolean have_regex;
        gboolean have_uid;
} UserData;

static uid_t
_util_name_to_uid (const char *username, gid_t *default_gid)
{
        int rc;
        uid_t res;
        char *buf = NULL;
        unsigned int bufsize;
        struct passwd pwd;
        struct passwd *pwdp;

        res = (uid_t) -1;

        bufsize = sysconf (_SC_GETPW_R_SIZE_MAX);
        buf = g_new0 (char, bufsize);
                
        rc = getpwnam_r (username, &pwd, buf, bufsize, &pwdp);
        if (rc != 0 || pwdp == NULL) {
                /*g_warning ("getpwnam_r() returned %d", rc);*/
                goto out;
        }

        res = pwdp->pw_uid;
        if (default_gid != NULL)
                *default_gid = pwdp->pw_gid;

out:
        g_free (buf);
        return res;
}

static gboolean
_module_init (PolKitModuleInterface *module_interface, int argc, char *argv[])
{
        int n;
        UserData *user_data;

        user_data = g_new0 (UserData, 1);
        for (n = 1; n < argc; n++) {
                if (g_str_has_prefix (argv[n], "privilege=")) {
                        const char *regex;
                        regex = argv[n] + 10;
                        if (regcomp (&(user_data->preg), regex, REG_EXTENDED) != 0) {
                                printf ("Regex '%s' didn't compile\n", regex);
                                goto error;
                        }
                        user_data->have_regex = TRUE;
                } else if (g_str_has_prefix (argv[n], "user=")) {
                        const char *user;
                        user = argv[n] + 5;
                        user_data->uid = _util_name_to_uid (user, NULL);
                        if ((int) user_data->uid == -1)
                                goto error;
                        user_data->have_uid = TRUE;
                }
        }

        libpolkit_module_set_user_data (module_interface, user_data);

        return TRUE;
error:
        g_free (user_data);
        return FALSE;
}

static void
_module_shutdown (PolKitModuleInterface *module_interface)
{
        UserData *user_data;
        user_data = libpolkit_module_get_user_data (module_interface);
        g_free (user_data);
}

static PolKitResult
_module_can_session_access_resource (PolKitModuleInterface *module_interface,
                                     PolKitContext         *pk_context,
                                     PolKitPrivilege       *privilege,
                                     PolKitResource        *resource,
                                     PolKitSession         *session)
{
        UserData *user_data;
        PolKitResult result;
        gboolean user_check_ok;
        gboolean regex_check_ok;

        user_check_ok = FALSE;
        regex_check_ok = FALSE;

        user_data = libpolkit_module_get_user_data (module_interface);

        if (user_data->have_regex) {
                char *privilege_name;
                if (libpolkit_privilege_get_privilege_id (privilege, &privilege_name)) {
                        if (regexec (&user_data->preg, privilege_name, 0, NULL, 0) == 0) {
                                regex_check_ok = TRUE;
                        }
                }
        } else {
                regex_check_ok = TRUE;
        }

        if (user_data->have_uid) {
                if (session != NULL) {
                        uid_t session_uid;
                        if (libpolkit_session_get_uid (session, &session_uid) && session_uid == user_data->uid) {
                                user_check_ok = TRUE;
                        }
                }
        } else {
                user_check_ok = TRUE;
        }

        if (user_check_ok && regex_check_ok) {
#ifdef IS_POLKIT_MODULE_DENY_ALL
                result = LIBPOLKIT_RESULT_NO;
#else
                result = LIBPOLKIT_RESULT_YES;
#endif
        } else {
                result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
        }
        return result;
}

static PolKitResult
_module_can_caller_access_resource (PolKitModuleInterface *module_interface,
                                    PolKitContext         *pk_context,
                                    PolKitPrivilege       *privilege,
                                    PolKitResource        *resource,
                                    PolKitCaller          *caller)
{
        UserData *user_data;
        PolKitResult result;
        gboolean user_check_ok;
        gboolean regex_check_ok;

        user_check_ok = FALSE;
        regex_check_ok = FALSE;

        user_data = libpolkit_module_get_user_data (module_interface);

        if (user_data->have_regex) {
                char *privilege_name;
                if (libpolkit_privilege_get_privilege_id (privilege, &privilege_name)) {
                        if (regexec (&user_data->preg, privilege_name, 0, NULL, 0) == 0) {
                                regex_check_ok = TRUE;
                        }
                }
        } else {
                regex_check_ok = TRUE;
        }

        if (user_data->have_uid) {
                uid_t caller_uid;
                if (libpolkit_caller_get_uid (caller, &caller_uid) && caller_uid == user_data->uid) {
                        user_check_ok = TRUE;
                }
        } else {
                user_check_ok = TRUE;
        }

        if (user_check_ok && regex_check_ok) {
#ifdef IS_POLKIT_MODULE_DENY_ALL
                result = LIBPOLKIT_RESULT_NO;
#else
                result = LIBPOLKIT_RESULT_YES;
#endif
        } else {
                result = LIBPOLKIT_RESULT_UNKNOWN_PRIVILEGE;
        }
        return result;
}

gboolean
libpolkit_module_set_functions (PolKitModuleInterface *module_interface)
{
        gboolean ret;

        ret = FALSE;
        if (module_interface == NULL)
                goto out;

        libpolkit_module_set_func_initialize (module_interface, _module_init);
        libpolkit_module_set_func_shutdown (module_interface, _module_shutdown);
        libpolkit_module_set_func_can_session_access_resource (module_interface, _module_can_session_access_resource);
        libpolkit_module_set_func_can_caller_access_resource (module_interface, _module_can_caller_access_resource);

        ret = TRUE;
out:
        return ret;
}

/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <security/pam_appl.h>

#include <polkit/polkit.h>

#ifndef HAVE_CLEARENV
extern char **environ;

static int
clearenv (void)
{
        if (environ != NULL)
                environ[0] = NULL;
        return 0;
}
#endif

static void
usage (int argc, char *argv[])
{
  g_printerr ("pkexec --version |\n"
              "       --help |\n"
              "       [--user username] PROGRAM [ARGUMENTS...]\n"
              "\n"
              "See the pkexec manual page for more details.\n");
}

/* ---------------------------------------------------------------------------------------------------- */

static int
pam_conversation_function (int n,
                           const struct pam_message **msg,
                           struct pam_response **resp,
                           void *data)
{
  g_assert_not_reached ();
  return PAM_CONV_ERR;
}

static gboolean
open_session (const gchar *user_to_auth)
{
  gboolean ret;
  gint rc;
  pam_handle_t *pam_h;
  struct pam_conv conversation;

  ret = FALSE;

  pam_h = NULL;

  conversation.conv        = pam_conversation_function;
  conversation.appdata_ptr = NULL;

  /* start the pam stack */
  rc = pam_start ("polkit-1",
                  user_to_auth,
                  &conversation,
                  &pam_h);
  if (rc != PAM_SUCCESS)
    {
      g_printerr ("pam_start() failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  /* open a session */
  rc = pam_open_session (pam_h,
                         0); /* flags */
  if (rc != PAM_SUCCESS)
    {
      g_printerr ("pam_open_session() failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  ret = TRUE;

out:
  if (pam_h != NULL)
    pam_end (pam_h, rc);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

typedef gboolean (*FdCallback) (gint fd, gpointer user_data);

static gboolean
set_close_on_exec (gint     fd,
                   gpointer user_data)
{
  gint fd_bottom;

  fd_bottom = GPOINTER_TO_INT (user_data);

  if (fd >= fd_bottom)
    {
      if (fcntl (fd, F_SETFD, FD_CLOEXEC) != 0 && errno != EBADF)
        {
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
fdwalk (FdCallback callback,
        gpointer   user_data)
{
  gint fd;
  gint max_fd;

  g_return_val_if_fail (callback != NULL, FALSE);

  max_fd = sysconf (_SC_OPEN_MAX);
  for (fd = 0; fd < max_fd; fd++)
    {
      if (!callback (fd, user_data))
        return FALSE;
    }

  return TRUE;
}

/* ---------------------------------------------------------------------------------------------------- */

static gchar *
find_action_for_path (PolkitAuthority *authority,
                      const gchar     *path)
{
  GList *l;
  GList *actions;
  gchar *action_id;
  GError *error;

  actions = NULL;
  action_id = NULL;
  error = NULL;

  actions = polkit_authority_enumerate_actions_sync (authority,
                                                     NULL,
                                                     &error);
  if (actions == NULL)
    {
      g_warning ("Error enumerating actions: %s", error->message);
      g_error_free (error);
      goto out;
    }

  for (l = actions; l != NULL; l = l->next)
    {
      PolkitActionDescription *action_desc = POLKIT_ACTION_DESCRIPTION (l->data);
      const gchar *path_for_action;

      path_for_action = polkit_action_description_get_annotation (action_desc, "org.freedesktop.policykit.exec.path");
      if (path_for_action == NULL)
        continue;

      if (g_strcmp0 (path_for_action, path) == 0)
        {
          action_id = g_strdup (polkit_action_description_get_action_id (action_desc));
          goto out;
        }
    }

 out:
  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  /* Fall back to org.freedesktop.policykit.exec */

  if (action_id == NULL)
    action_id = g_strdup ("org.freedesktop.policykit.exec");

  return action_id;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
is_valid_shell (const gchar *shell)
{
  gboolean ret;
  gchar *contents;
  gchar **shells;
  GError *error;
  guint n;

  ret = FALSE;

  contents = NULL;
  shells = NULL;

  error = NULL;
  if (!g_file_get_contents ("/etc/shells",
                            &contents,
                            NULL, /* gsize *length */
                            &error))
    {
      g_printerr ("Error getting contents of /etc/shells: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  shells = g_strsplit (contents, "\n", 0);
  for (n = 0; shells != NULL && shells[n] != NULL; n++)
    {
      if (g_strcmp0 (shell, shells[n]) == 0)
        {
          ret = TRUE;
          goto out;
        }
    }

 out:
  g_free (contents);
  g_strfreev (shells);
  return ret;
}

static gboolean
validate_environment_variable (const gchar *key,
                               const gchar *value)
{
  gboolean ret;

  /* Generally we bail if any environment variable value contains
   *
   *   - '/' characters
   *   - '%' characters
   *   - '..' substrings
   */

  g_return_val_if_fail (key != NULL, FALSE);
  g_return_val_if_fail (value != NULL, FALSE);

  ret = FALSE;

  /* special case $SHELL */
  if (g_strcmp0 (key, "SHELL") == 0)
    {
      /* check if it's in /etc/shells */
      if (!is_valid_shell (value))
        {
          g_printerr ("The value for environment variable SHELL is not included in the\n"
                      "/etc/shells file. This incident will be reported. Bailing out.\n");
          /* TODO: syslog */
          goto out;
        }
    }
  else if (strstr (value, "/") != NULL ||
           strstr (value, "%") != NULL ||
           strstr (value, "..") != NULL)
    {
      g_printerr ("The value for environment variable %s contains suscipious content\n"
                  "indicating an exploit. This incident will be reported. Bailing out.\n",
                  key);
      /* TODO: syslog */
      goto out;
    }

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

int
main (int argc, char *argv[])
{
  guint n;
  guint ret;
  gint rc;
  gboolean opt_show_help;
  gboolean opt_show_version;
  PolkitAuthority *authority;
  PolkitAuthorizationResult *result;
  PolkitSubject *subject;
  PolkitDetails *details;
  GError *error;
  gchar *action_id;
  gchar *command_line;
  gchar **exec_argv;
  gchar *path;
  struct passwd pwstruct;
  struct passwd *pw;
  gchar pwbuf[8192];
  gchar *s;
  const gchar *environment_variables_to_save[] = {
    "SHELL",
    "LANG",
    "LINGUAS",
    "LANGUAGE",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_ALL",
    "TERM",
    "COLORTERM",

    /* For now, avoiding pretend that running X11 apps as another user in the same session
     * will ever work... See
     *
     *  https://bugs.freedesktop.org/show_bug.cgi?id=17970#c26
     *
     * and surrounding comments for a lot of discussion about this.
     */
#if 0
    "DESKTOP_STARTUP_ID",
    "DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "ORBIT_SOCKETDIR",
#endif
    NULL
  };
  GPtrArray *saved_env;
  gchar *opt_user;
  pid_t pid_of_caller;
  uid_t uid_of_caller;
  struct stat statbuf;

  ret = 127;
  authority = NULL;
  subject = NULL;
  details = NULL;
  result = NULL;
  action_id = NULL;
  saved_env = NULL;
  path = NULL;
  command_line = NULL;
  opt_user = NULL;

  /* check for correct invocation */
  if (geteuid () != 0)
    {
      g_print ("pkexec must be setuid root\n");
      goto out;
    }

  /* First process options and find the command-line to invoke. Avoid using fancy library routines
   * that depend on environtment variables since we haven't cleared the environment just yet.
   */
  opt_show_help = FALSE;
  opt_show_version = FALSE;
  for (n = 1; n < (guint) argc; n++)
    {
      if (strcmp (argv[n], "--help") == 0)
        {
          opt_show_help = TRUE;
        }
      else if (strcmp (argv[n], "--version") == 0)
        {
          opt_show_version = TRUE;
        }
      else if (strcmp (argv[n], "--user") == 0 || strcmp (argv[n], "-u") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          opt_user = g_strdup (argv[n]);
        }
      else
        {
          break;
        }
    }

  if (opt_show_help)
    {
      usage (argc, argv);
      ret = 0;
      goto out;
    }
  else if (opt_show_version)
    {
      g_print ("pkexec version %s\n", PACKAGE_VERSION);
      ret = 0;
      goto out;
    }

  if (opt_user == NULL)
    opt_user = g_strdup ("root");

  /* Now figure out the command-line to run - argv is guaranteed to be NULL-terminated, see
   *
   *  http://lkml.indiana.edu/hypermail/linux/kernel/0409.2/0287.html
   *
   * but do check this is the case.
   *
   * We also try to locate the program in the path if a non-absolute path is given.
   */
  g_assert (argv[argc] == NULL);
  path = g_strdup (argv[n]);
  if (path == NULL)
    {
      usage (argc, argv);
      goto out;
    }
  if (path[0] != '/')
    {
      /* g_find_program_in_path() is not suspectible to attacks via the environment */
      s = g_find_program_in_path (path);
      if (s == NULL)
        {
          g_printerr ("Cannot run program %s: %s\n", path, strerror (ENOENT));
          goto out;
        }
      g_free (path);
      argv[n] = path = s;
    }
  if (stat (path, &statbuf) != 0)
    {
      g_printerr ("Error getting information about %s: %s\n", path, g_strerror (errno));
      goto out;
    }
  command_line = g_strjoinv (" ", argv + n);
  exec_argv = argv + n;

  /* now save the environment variables we care about */
  saved_env = g_ptr_array_new ();
  for (n = 0; environment_variables_to_save[n] != NULL; n++)
    {
      const gchar *key = environment_variables_to_save[n];
      const gchar *value;

      value = g_getenv (key);
      if (value == NULL)
        continue;

      /* To qualify for the paranoia goldstar - we validate the value of each
       * environment variable passed through - this is to attempt to avoid
       * exploits in (potentially broken) programs launched via pkexec(1).
       */
      if (!validate_environment_variable (key, value))
        goto out;

      g_ptr_array_add (saved_env, g_strdup (key));
      g_ptr_array_add (saved_env, g_strdup (value));
    }

  /* Nuke the environment to get a well-known and sanitized environment to avoid attacks
   * via e.g. the DBUS_SYSTEM_BUS_ADDRESS environment variable and similar.
   */
  if (clearenv () != 0)
    {
      g_printerr ("Error clearing environment: %s\n", g_strerror (errno));
      goto out;
    }

  /* Look up information about the user we care about - yes, the return
   * value of this function is a bit funky
   */
  rc = getpwnam_r (opt_user, &pwstruct, pwbuf, sizeof pwbuf, &pw);
  if (rc == 0 && pw == NULL)
    {
      g_printerr ("User `%s' does not exist.\n", opt_user);
      goto out;
    }
  else if (pw == NULL)
    {
      g_printerr ("Error getting information for user `%s': %s\n", opt_user, g_strerror (rc));
      goto out;
    }

  /* Initialize the GLib type system - this is needed to interact with the
   * PolicyKit daemon
   */
  g_type_init ();

  /* now check if the program that invoked us is authorized */
  pid_of_caller = getppid ();
  if (pid_of_caller == 1)
    {
      /* getppid() can return 1 if the parent died (meaning that we are reaped
       * by /sbin/init); get process group leader instead - for example, this
       * happens when launching via gnome-panel (alt+f2, then 'pkexec gedit').
       */
      pid_of_caller = getpgrp ();
    }

  subject = polkit_unix_process_new (pid_of_caller);
  if (subject == NULL)
    {
      g_printerr ("No such process for pid %d: %s\n", (gint) pid_of_caller, error->message);
      g_error_free (error);
      goto out;
    }

  /* paranoia: check that the uid of pid_of_caller matches getuid() */
  error = NULL;
  uid_of_caller = polkit_unix_process_get_owner (POLKIT_UNIX_PROCESS (subject),
                                                 &error);
  if (error != NULL)
    {
      g_printerr ("Error determing pid of caller (pid %d): %s\n", (gint) pid_of_caller, error->message);
      g_error_free (error);
      goto out;
    }
  if (uid_of_caller != getuid ())
    {
      g_printerr ("User of caller (%d) does not match our uid (%d)\n", uid_of_caller, getuid ());
      goto out;
    }

  authority = polkit_authority_get ();

  details = polkit_details_new ();

  polkit_details_insert (details, "command-line", command_line);
  s = g_strdup_printf ("%s (%s)", pw->pw_gecos, pw->pw_name);
  polkit_details_insert (details, "user", s);
  g_free (s);
  s = g_strdup_printf ("%d", (gint) pw->pw_uid);
  polkit_details_insert (details, "uid", s);
  g_free (s);
  polkit_details_insert (details, "program", path);

  action_id = find_action_for_path (authority, path);
  g_assert (action_id != NULL);

  error = NULL;
  result = polkit_authority_check_authorization_sync (authority,
                                                      subject,
                                                      action_id,
                                                      details,
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                                      NULL,
                                                      &error);
  if (result == NULL)
    {
      g_printerr ("Error checking for authorization %s: %s\n",
                  action_id,
                  error->message);
      goto out;
    }

  if (polkit_authorization_result_get_is_authorized (result))
    {
      /* do nothing */
    }
  else if (polkit_authorization_result_get_is_challenge (result))
    {
      g_printerr ("Authorization requires authentication but no authentication agent was found.\n");
      /* TODO: syslog */
      goto out;
    }
  else
    {
      g_printerr ("Not authorized.\n");
      /* TODO: syslog */
      goto out;
    }

  /* Set PATH to a safe list */
  g_ptr_array_add (saved_env, g_strdup ("PATH"));
  if (pw->pw_uid != 0)
    s = g_strdup_printf ("/usr/bin:/bin:/usr/sbin:/sbin:%s/bin", pw->pw_dir);
  else
    s = g_strdup_printf ("/usr/sbin:/usr/bin:/sbin:/bin:%s/bin", pw->pw_dir);
  g_ptr_array_add (saved_env, s);
  g_ptr_array_add (saved_env, g_strdup ("LOGNAME"));
  g_ptr_array_add (saved_env, g_strdup (pw->pw_name));
  g_ptr_array_add (saved_env, g_strdup ("USER"));
  g_ptr_array_add (saved_env, g_strdup (pw->pw_name));
  g_ptr_array_add (saved_env, g_strdup ("HOME"));
  g_ptr_array_add (saved_env, g_strdup (pw->pw_dir));

  s = g_strdup_printf ("%d", getuid ());
  g_ptr_array_add (saved_env, g_strdup ("PKEXEC_UID"));
  g_ptr_array_add (saved_env, s);

  /* set the environment */
  for (n = 0; n < saved_env->len - 1; n += 2)
    {
      const gchar *key = saved_env->pdata[n];
      const gchar *value = saved_env->pdata[n + 1];

      if (!g_setenv (key, value, TRUE))
        {
          g_printerr ("Error setting environment variable %s to '%s': %s\n",
                      key,
                      value,
                      g_strerror (errno));
          goto out;
        }
    }

  /* set close_on_exec on all file descriptors except stdin, stdout, stderr */
  if (!fdwalk (set_close_on_exec, GINT_TO_POINTER (3)))
    {
      g_printerr ("Error setting close-on-exec for file desriptors\n");
      goto out;
    }

  /* if not changing to uid 0, become uid 0 before changing to the user */
  if (pw->pw_uid != 0)
    {
      setreuid (0, 0);
      if ((geteuid () != 0) || (getuid () != 0))
        {
          g_printerr ("Error becoming uid 0: %s\n", g_strerror (errno));
          goto out;
        }
    }

  /* open session - with PAM enabled, this runs the open_session() part of the PAM
   * stack - this includes applying limits via pam_limits.so but also other things
   * requested via the current PAM configuration.
   *
   * NOTE NOTE NOTE: pam_limits.so doesn't seem to clear existing limits - e.g.
   *
   *  $ ulimit -t
   *  unlimited
   *
   *  $ su -
   *  Password:
   *  # ulimit -t
   *  unlimited
   *  # logout
   *
   *  $ ulimit -t 1000
   *  $ ulimit -t
   *  1000
   *  $ su -
   *  Password:
   *  # ulimit -t
   *  1000
   *
   * TODO: The question here is whether we should clear the limits before applying them?
   * As evident above, neither su(1) (and, for that matter, nor sudo(8)) does this.
   */
  if (!open_session (pw->pw_name))
    {
      goto out;
    }

  /* become the user */
  if (setgroups (0, NULL) != 0)
    {
      g_printerr ("Error setting groups: %s\n", g_strerror (errno));
      goto out;
    }
  if (initgroups (pw->pw_name, pw->pw_gid) != 0)
    {
      g_printerr ("Error initializing groups for %s: %s\n", pw->pw_name, g_strerror (errno));
      goto out;
    }
  setregid (pw->pw_gid, pw->pw_gid);
  setreuid (pw->pw_uid, pw->pw_uid);
  if ((geteuid () != pw->pw_uid) || (getuid () != pw->pw_uid) ||
      (getegid () != pw->pw_gid) || (getgid () != pw->pw_gid))
    {
      g_printerr ("Error becoming real+effective uid %d and gid %d: %s\n", pw->pw_uid, pw->pw_gid, g_strerror (errno));
      goto out;
    }

  /* change to home directory */
  if (chdir (pw->pw_dir) != 0)
    {
      g_printerr ("Error changing to home directory %s: %s\n", pw->pw_dir, g_strerror (errno));
      goto out;
    }

  /* TODO: syslog */

  /* exec the program */
  if (execv (path, exec_argv) != 0)
    {
      g_printerr ("Error executing %s: %s\n", path, g_strerror (errno));
      goto out;
    }

  /* if exec doesn't fail, it never returns... */
  g_assert_not_reached ();

 out:
  if (result != NULL)
    g_object_unref (result);

  g_free (action_id);

  if (details != NULL)
    g_object_unref (details);

  if (subject != NULL)
    g_object_unref (subject);

  if (authority != NULL)
    g_object_unref (authority);

  if (saved_env != NULL)
    {
      g_ptr_array_foreach (saved_env, (GFunc) g_free, NULL);
      g_ptr_array_free (saved_env, TRUE);
    }

  g_free (path);
  g_free (command_line);
  g_free (opt_user);

  return ret;
}


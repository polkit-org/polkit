/*
 * Copyright (C) 2008-2010 Red Hat, Inc.
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

#include "config.h"

#include <signal.h>
#include <stdlib.h>

#include <glib-unix.h>

#include <pwd.h>
#include <grp.h>

#include <polkit/polkit.h>
#include <polkitbackend/polkitbackend.h>

/* ---------------------------------------------------------------------------------------------------- */

static PolkitBackendAuthority *authority = NULL;
static gpointer                registration_id = NULL;
static GMainLoop              *loop = NULL;
static gint                    exit_status = EXIT_FAILURE;
static gboolean                opt_replace = FALSE;
static gboolean                opt_no_debug = FALSE;
static GOptionEntry            opt_entries[] = {
  {"replace", 'r', 0, G_OPTION_ARG_NONE, &opt_replace, "Replace existing daemon", NULL},
  {"no-debug", 'n', 0, G_OPTION_ARG_NONE, &opt_no_debug, "Don't print debug information", NULL},
  {NULL }
};

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
  GError *error;

  g_print ("Connected to the system bus\n");

  g_assert (registration_id == NULL);

  error = NULL;
  registration_id = polkit_backend_authority_register (authority,
                                                       connection,
                                                       "/org/freedesktop/PolicyKit1/Authority",
                                                       &error);
  if (registration_id == NULL)
    {
      g_printerr ("Error registering authority: %s\n", error->message);
      g_error_free (error);
      g_main_loop_quit (loop); /* exit */
    }
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Lost the name org.freedesktop.PolicyKit1 - exiting");
  g_main_loop_quit (loop);
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
  exit_status = EXIT_SUCCESS;

  polkit_backend_authority_log (POLKIT_BACKEND_AUTHORITY (authority),
                                "Acquired the name org.freedesktop.PolicyKit1 on the system bus");
}

static gboolean
on_sigint (gpointer user_data)
{
  g_print ("Handling SIGINT\n");
  g_main_loop_quit (loop);
  return TRUE;
}

static gboolean
become_user (const gchar  *user,
             GError      **error)
{
  gboolean ret = FALSE;
  struct passwd *pw;

  g_return_val_if_fail (user != NULL, FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  pw = getpwnam (user);
  if (pw == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Error calling getpwnam(): %m");
      goto out;
    }

  if ((geteuid () == pw->pw_uid) && (getuid () == pw->pw_uid) &&
      (getegid () == pw->pw_gid) && (getgid () == pw->pw_gid))
    {
      /* already running as user */
      ret = TRUE;
      goto out;
    }

  if (setgroups (0, NULL) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Error clearing groups: %m");
      goto out;
    }
  if (initgroups (pw->pw_name, pw->pw_gid) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Error initializing groups: %m");
      goto out;
    }

  setregid (pw->pw_gid, pw->pw_gid);
  setreuid (pw->pw_uid, pw->pw_uid);
  if ((geteuid () != pw->pw_uid) || (getuid () != pw->pw_uid) ||
      (getegid () != pw->pw_gid) || (getgid () != pw->pw_gid))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Error becoming real+effective uid %d and gid %d: %m",
                   (int) pw->pw_uid, (int) pw->pw_gid);
      goto out;
    }

  if (chdir (pw->pw_dir) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Error changing to home directory %s: %m",
                   pw->pw_dir);
      goto out;
    }


  ret = TRUE;
  g_print ("Successfully changed to user %s\n", user);

 out:
  return ret;
}

int
main (int    argc,
      char **argv)
{
  GError *error;
  GOptionContext *opt_context;
  guint name_owner_id;
  guint sigint_id;

  loop = NULL;
  opt_context = NULL;
  name_owner_id = 0;
  sigint_id = 0;
  registration_id = NULL;

  /* Disable remote file access from GIO. */
  setenv ("GIO_USE_VFS", "local", 1);

  opt_context = g_option_context_new ("polkit system daemon");
  g_option_context_add_main_entries (opt_context, opt_entries, NULL);
  error = NULL;
  if (!g_option_context_parse (opt_context, &argc, &argv, &error))
    {
      g_printerr ("Error parsing options: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  /* If --no-debug is requested don't clutter stdout/stderr etc.
   */
  if (opt_no_debug)
    {
      gint dev_null_fd;
      dev_null_fd = open ("/dev/null", O_RDWR);
      if (dev_null_fd >= 0)
        {
          dup2 (dev_null_fd, STDIN_FILENO);
          dup2 (dev_null_fd, STDOUT_FILENO);
          dup2 (dev_null_fd, STDERR_FILENO);
          close (dev_null_fd);
        }
      else
        {
          g_warning ("Error opening /dev/null: %m");
        }
    }

  error = NULL;
  if (!become_user (POLKITD_USER, &error))
    {
      g_printerr ("Error switching to user %s: %s\n",
                  POLKITD_USER, error->message);
      g_clear_error (&error);
      goto out;
    }

  if (g_getenv ("PATH") == NULL)
    g_setenv ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", TRUE);

  authority = polkit_backend_authority_get ();

  loop = g_main_loop_new (NULL, FALSE);

  sigint_id = g_unix_signal_add (SIGINT,
                                 on_sigint,
                                 NULL);

  name_owner_id = g_bus_own_name (G_BUS_TYPE_SYSTEM,
                                  "org.freedesktop.PolicyKit1",
                                  G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT |
                                    (opt_replace ? G_BUS_NAME_OWNER_FLAGS_REPLACE : 0),
                                  on_bus_acquired,
                                  on_name_acquired,
                                  on_name_lost,
                                  NULL,
                                  NULL);

  g_print ("Entering main event loop\n");
  g_main_loop_run (loop);

  g_print ("Shutting down\n");
 out:
  if (sigint_id > 0)
    g_source_remove (sigint_id);
  if (name_owner_id != 0)
    g_bus_unown_name (name_owner_id);
  if (registration_id != NULL)
    polkit_backend_authority_unregister (registration_id);
  if (authority != NULL)
    g_object_unref (authority);
  if (loop != NULL)
    g_main_loop_unref (loop);
  if (opt_context != NULL)
    g_option_context_free (opt_context);

  g_print ("Exiting with code %d\n", exit_status);
  return exit_status;
}

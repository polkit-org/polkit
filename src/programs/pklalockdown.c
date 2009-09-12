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
#include <glib/gstdio.h>

#include <polkit/polkit.h>

static gchar *get_lockdown_filename (const gchar *action_id);
static gboolean lockdown_exists (const gchar *action_id);


static void
usage (int argc, char *argv[])
{
  GError *error;

  error = NULL;
  if (!g_spawn_command_line_sync ("man pklalockdown",
                                  NULL,
                                  NULL,
                                  NULL,
                                  &error))
    {
      g_printerr ("Cannot show manual page: %s\n", error->message);
      g_error_free (error);
    }
}

int
main (int argc, char *argv[])
{
  guint n;
  guint ret;
  gboolean opt_show_help;
  gboolean opt_show_version;
  gchar *opt_lockdown;
  gchar *opt_remove_lockdown;

  ret = 1;

  opt_show_help = FALSE;
  opt_show_version = FALSE;
  opt_lockdown = NULL;
  opt_remove_lockdown = NULL;

  /* if we are not yet uid 0, make us uid 0 through pkexec */
  if (getuid () != 0)
    {
      gchar **exec_argv;

      exec_argv = g_new0 (gchar *, argc + 2);
      exec_argv[0] = PACKAGE_BIN_DIR "/pkexec";
      memcpy (exec_argv + 1, argv, argc * sizeof (gchar *));

      if (execv (PACKAGE_BIN_DIR "/pkexec", exec_argv) != 0)
        {
          g_printerr ("Error executing " PACKAGE_BIN_DIR "/pkexec: %s\n", g_strerror (errno));
          goto out;
        }

      g_assert_not_reached ();
    }

  /* We are now uid 0 (by default, the user had to authenticate to get
   * here) - be careful to check all incoming args
   */
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
      else if (strcmp (argv[n], "--lockdown") == 0 || strcmp (argv[n], "-l") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          opt_lockdown = g_strdup (argv[n]);
        }
      else if (strcmp (argv[n], "--remove-lockdown") == 0 || strcmp (argv[n], "-r") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          opt_remove_lockdown = g_strdup (argv[n]);
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
  else if (opt_lockdown != NULL)
    {
      gchar *filename;
      gchar *contents;
      GError *error;

      if (lockdown_exists (opt_lockdown))
        {
          g_printerr ("Error: action %s is already locked down\n", opt_lockdown);
          goto out;
        }

      filename = get_lockdown_filename (opt_lockdown);
      contents = g_strdup_printf ("# Added by pklalockdown(1)\n"
                                  "#\n"
                                  "[Lockdown]\n"
                                  "Identity=unix-user:*\n"
                                  "Action=%s\n"
                                  "ResultAny=no\n"
                                  "ResultInactive=no\n"
                                  "ResultActive=auth_admin_keep\n"
                                  "ReturnValue=polkit.localauthority.lockdown=1",
                                  opt_lockdown);
      error = NULL;
      if (!g_file_set_contents (filename,
                                contents,
                                -1,
                                &error))
        {
          g_printerr ("Error: Cannot write to file %s: %s\n", filename, error->message);
          g_error_free (error);
          g_free (filename);
          g_free (contents);
          goto out;
        }
      g_free (filename);
      g_free (contents);
      ret = 0;
      goto out;
    }
  else if (opt_remove_lockdown != NULL)
    {
      gchar *filename;

      if (!lockdown_exists (opt_remove_lockdown))
        {
          g_printerr ("Error: action %s is not locked down\n", opt_remove_lockdown);
          goto out;
        }

      filename = get_lockdown_filename (opt_remove_lockdown);
      if (g_unlink (filename) != 0)
        {
          g_printerr ("Error: Cannot unlink file %s: %s\n", filename, g_strerror (errno));
          g_free (filename);
          goto out;
        }
      g_free (filename);

      ret = 0;
      goto out;
    }

  usage (argc, argv);

 out:
  g_free (opt_lockdown);
  g_free (opt_remove_lockdown);
  return ret;
}

static gchar *
get_lockdown_filename (const gchar *action_id)
{
  return g_strdup_printf (PACKAGE_LOCALSTATE_DIR
                          "/lib/polkit-1/localauthority/90-mandatory.d/"
                          "org.freedesktop.policykit.localauthority.lockdown.action-%s.pkla",
                          action_id);
}

static gboolean
lockdown_exists (const gchar *action_id)
{
  gchar *filename;
  gboolean ret;

  ret = FALSE;

  filename = get_lockdown_filename (action_id);
  if (g_file_test (filename, G_FILE_TEST_IS_REGULAR | G_FILE_TEST_EXISTS))
    ret = TRUE;
  g_free (filename);

  return ret;
}


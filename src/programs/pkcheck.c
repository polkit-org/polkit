/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#include <stdio.h>
#include <polkit/polkit.h>

static void
usage (int argc, char *argv[])
{
  GError *error;

  error = NULL;
  if (!g_spawn_command_line_sync ("man pkcheck",
                                  NULL,
                                  NULL,
                                  NULL,
                                  &error))
    {
      g_printerr ("Cannot show manual page: %s\n", error->message);
      g_error_free (error);
    }
}

static gchar *
escape_str (const gchar *str)
{
  GString *s;
  guint n;

  s = g_string_new (NULL);
  if (str == NULL)
    goto out;

  for (n = 0; str[n] != '\0'; n++)
    {
      guint c = str[n] & 0xff;

      if (g_ascii_isalnum (c) || c=='_')
        g_string_append_c (s, c);
      else
        g_string_append_printf (s, "\\%o", c);
    }

 out:
  return g_string_free (s, FALSE);
}


int
main (int argc, char *argv[])
{
  guint n;
  guint ret;
  gchar *action_id;
  gboolean opt_show_help;
  gboolean opt_show_version;
  gboolean allow_user_interaction;
  PolkitAuthority *authority;
  PolkitAuthorizationResult *result;
  PolkitSubject *subject;
  PolkitDetails *details;
  PolkitCheckAuthorizationFlags flags;
  PolkitDetails *result_details;
  GError *error;

  subject = NULL;
  action_id = NULL;
  details = NULL;
  authority = NULL;
  result = NULL;
  allow_user_interaction = FALSE;
  ret = 126;

  g_type_init ();

  details = polkit_details_new ();

  opt_show_help = FALSE;
  opt_show_version = FALSE;
  for (n = 1; n < (guint) argc; n++)
    {
      if (g_strcmp0 (argv[n], "--help") == 0)
        {
          opt_show_help = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--version") == 0)
        {
          opt_show_version = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--process") == 0 || g_strcmp0 (argv[n], "-p") == 0)
        {
          gint pid;
          guint64 pid_start_time;

          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          if (sscanf (argv[n], "%i,%" G_GUINT64_FORMAT, &pid, &pid_start_time) == 2)
            {
              subject = polkit_unix_process_new_full (pid, pid_start_time);
            }
          else if (sscanf (argv[n], "%i", &pid) == 1)
            {
              subject = polkit_unix_process_new (pid);
            }
          else
            {
              usage (argc, argv);
              goto out;
            }
        }
      else if (g_strcmp0 (argv[n], "--system-bus-name") == 0 || g_strcmp0 (argv[n], "-s") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          subject = polkit_system_bus_name_new (argv[n]);
        }
      else if (g_strcmp0 (argv[n], "--action-id") == 0 || g_strcmp0 (argv[n], "-a") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          action_id = g_strdup (argv[n]);
        }
      else if (g_strcmp0 (argv[n], "--detail") == 0 || g_strcmp0 (argv[n], "-d") == 0)
        {
          const gchar *key;
          const gchar *value;

          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }
          key = argv[n];

          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }
          value = argv[n];

          polkit_details_insert (details, key, value);
        }
      else if (g_strcmp0 (argv[n], "--allow-user-interaction") == 0 || g_strcmp0 (argv[n], "-u") == 0)
        {
          allow_user_interaction = TRUE;
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

  if (subject == NULL)
    {
      usage (argc, argv);
      goto out;
    }

  error = NULL;
  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_printerr ("Error getting authority: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;
  if (allow_user_interaction)
    flags |= POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;
  result = polkit_authority_check_authorization_sync (authority,
                                                      subject,
                                                      action_id,
                                                      details,
                                                      flags,
                                                      NULL,
                                                      &error);
  if (result == NULL)
    {
      g_printerr ("Error checking for authorization %s: %s\n",
                  action_id,
                  error->message);
      ret = 127;
      goto out;
    }

  result_details = polkit_authorization_result_get_details (result);
  if (result_details != NULL)
    {
      gchar **keys;

      keys = polkit_details_get_keys (result_details);
      for (n = 0; keys != NULL && keys[n] != NULL; n++)
        {
          const gchar *key;
          const gchar *value;
          gchar *s;

          key = keys[n];
          value = polkit_details_lookup (result_details, key);

          s = escape_str (key);
          g_print ("%s", s);
          g_free (s);
          g_print ("=");
          s = escape_str (value);
          g_print ("%s", s);
          g_free (s);
          g_print ("\n");
        }

      g_strfreev (keys);
    }

  if (polkit_authorization_result_get_is_authorized (result))
    {
      ret = 0;
    }
  else if (polkit_authorization_result_get_is_challenge (result))
    {
      if (allow_user_interaction)
        g_printerr ("Authorization requires authentication but no agent is available.\n");
      else
        g_printerr ("Authorization requires authentication and -u wasn't passed.\n");
      ret = 2;
    }
  else
    {
      g_printerr ("Not authorized.\n");
      ret = 1;
    }

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

  return ret;
}

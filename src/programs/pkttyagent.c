/*
 * Copyright (C) 2009-2012 Red Hat, Inc.
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
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>

static void
usage (int argc, char *argv[])
{
  GError *error;

  error = NULL;
  if (!g_spawn_command_line_sync ("man pkttyagent",
                                  NULL,
                                  NULL,
                                  NULL,
                                  &error))
    {
      g_printerr ("Cannot show manual page: %s (%s, %d)\n",
                  error->message, g_quark_to_string (error->domain), error->code);
      g_error_free (error);
    }
}


int
main (int argc, char *argv[])
{
  gboolean opt_show_help = FALSE;
  gboolean opt_show_version = FALSE;
  gboolean opt_fallback = FALSE;
  PolkitAuthority *authority = NULL;
  PolkitSubject *subject = NULL;
  gpointer local_agent_handle = NULL;
  PolkitAgentListener *listener = NULL;
  GVariant *options = NULL;
  GError *error;
  GMainLoop *loop = NULL;
  guint n;
  guint ret = 126;
  gint notify_fd = -1;
  GVariantBuilder builder;

  g_type_init ();

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
      else if (g_strcmp0 (argv[n], "--fallback") == 0)
        {
          opt_fallback = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--notify-fd") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          if (sscanf (argv[n], "%i", &notify_fd) != 1)
            {
              usage (argc, argv);
              goto out;
            }
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
      g_print ("pkttyagent version %s\n", PACKAGE_VERSION);
      ret = 0;
      goto out;
    }

  /* Use parent process, if no subject has been specified */
  if (subject == NULL)
    {
      pid_t pid_of_caller;
      pid_of_caller = getppid ();
      if (pid_of_caller == 1)
        {
          /* getppid() can return 1 if the parent died (meaning that we are reaped
           * by /sbin/init); In that case we simpy bail.
           */
          g_printerr ("Refusing to render service to dead parents.\n");
          goto out;
        }

      subject = polkit_unix_process_new_for_owner (pid_of_caller,
                                                   0, /* 0 means "look up start-time in /proc" */
                                                   getuid ());
      /* really double-check the invariants guaranteed by the PolkitUnixProcess class */
      g_assert (subject != NULL);
      g_assert (polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject)) == pid_of_caller);
      g_assert (polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (subject)) >= 0);
      g_assert (polkit_unix_process_get_start_time (POLKIT_UNIX_PROCESS (subject)) > 0);
    }

  error = NULL;
  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_printerr ("Error getting authority: %s (%s, %d)\n",
                  error->message, g_quark_to_string (error->domain), error->code);
      g_error_free (error);
      ret = 127;
      goto out;
    }

  if (opt_fallback)
    {
      g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
      g_variant_builder_add (&builder, "{sv}", "fallback", g_variant_new_boolean (TRUE));
      options = g_variant_builder_end (&builder);
    }

  error = NULL;
  /* this will fail if we can't find a controlling terminal */
  listener = polkit_agent_text_listener_new (NULL, &error);
  if (listener == NULL)
    {
      g_printerr ("Error creating textual authentication agent: %s (%s, %d)\n",
                  error->message, g_quark_to_string (error->domain), error->code);
      g_error_free (error);
      ret = 127;
      goto out;
    }
  local_agent_handle = polkit_agent_listener_register_with_options (listener,
                                                                    POLKIT_AGENT_REGISTER_FLAGS_RUN_IN_THREAD,
                                                                    subject,
                                                                    NULL, /* object_path */
                                                                    options,
                                                                    NULL, /* GCancellable */
                                                                    &error);
  options = NULL; /* consumed */
  g_object_unref (listener);
  if (local_agent_handle == NULL)
    {
      g_printerr ("Error registering authentication agent: %s (%s, %d)\n",
                  error->message, g_quark_to_string (error->domain), error->code);
      g_error_free (error);
      goto out;
    }

  if (notify_fd != -1)
    {
      if (close (notify_fd) != 0)
        {
          g_printerr ("Error closing notify-fd %d: %m\n", notify_fd);
          goto out;
        }
    }

  loop = g_main_loop_new (NULL, FALSE);
  g_main_loop_run (loop);

 out:
  if (loop != NULL)
    g_main_loop_unref (loop);

  if (local_agent_handle != NULL)
    polkit_agent_listener_unregister (local_agent_handle);

  if (options != NULL)
    g_variant_unref (options);

  if (subject != NULL)
    g_object_unref (subject);

  if (authority != NULL)
    g_object_unref (authority);

  return ret;
}

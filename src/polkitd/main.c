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

#include <glib-unix.h>

#include <polkit/polkit.h>
#include <polkitbackend/polkitbackend.h>

#include "gposixsignal.h"

/* ---------------------------------------------------------------------------------------------------- */

static PolkitBackendAuthority *authority = NULL;
static gpointer                registration_id = NULL;
static GMainLoop              *loop = NULL;
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

  g_assert (authority == NULL);
  g_assert (registration_id == NULL);

  authority = polkit_backend_authority_get ();
  g_print ("Using authority class %s\n", g_type_name (G_TYPE_FROM_INSTANCE (authority)));

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
  g_print ("Lost the name org.freedesktop.PolicyKit1 - exiting\n");
  g_main_loop_quit (loop);
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
  g_print ("Acquired the name org.freedesktop.PolicyKit1\n");
}

static gboolean
on_sigint (gpointer user_data)
{
  g_print ("Handling SIGINT\n");
  g_main_loop_quit (loop);
  return FALSE;
}

int
main (int    argc,
      char **argv)
{
  GError *error;
  GOptionContext *opt_context;
  gint ret;
  guint name_owner_id;
  guint sigint_id;

  ret = 1;
  loop = NULL;
  opt_context = NULL;
  name_owner_id = 0;
  sigint_id = 0;
  registration_id = NULL;

  g_type_init ();

  opt_context = g_option_context_new ("polkit authority");
  g_option_context_add_main_entries (opt_context, opt_entries, NULL);
  error = NULL;
  if (!g_option_context_parse (opt_context, &argc, &argv, &error))
    {
      g_printerr ("Error parsing options: %s", error->message);
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


  loop = g_main_loop_new (NULL, FALSE);

  sigint_id = _g_posix_signal_watch_add (SIGINT,
                                         G_PRIORITY_DEFAULT,
                                         on_sigint,
                                         NULL,
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

  ret = 0;

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

  g_print ("Exiting with code %d\n", ret);
  return ret;
}

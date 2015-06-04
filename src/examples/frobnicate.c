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

#include "config.h"

#include <glib.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

int
main (int argc, char *argv[])
{
  gchar *args;
  gchar **env;
  guint n;
  int ret;
#ifdef __GLIBC__
  gchar *cwd = NULL;
#else
  gchar cwd[PATH_MAX];
#endif

  ret = 1;
  args = NULL;
  env = NULL;

#ifdef __GLIBC__
  if ((cwd = get_current_dir_name ()) == NULL)
#else
  if (getcwd (cwd, sizeof cwd) == NULL)
#endif
    {
      g_printerr ("Error getting cwd: %s\n", g_strerror (errno));
      goto out;
    }

  args = g_strjoinv (" ", argv);

  g_print ("In pk-example-frobnicate\n");
  g_print ("uid:           %d\n", getuid ());
  g_print ("euid:          %d\n", geteuid ());
  g_print ("args:         `%s'\n", args);
  g_print ("cwd:           %s\n", cwd);
  g_print ("environment:\n");

  env = g_listenv ();
  for (n = 0; env[n] != NULL; n++)
    {
      g_print ("  %s=%s\n", env[n], g_getenv (env[n]));
    }

  ret = 0;

 out:

#ifdef __GLIBC__
  free (cwd);
#endif
  g_free (args);
  g_strfreev (env);

  return ret;
}

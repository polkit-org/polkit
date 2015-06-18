/*
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 * Authors: David Zeuthen <davidz@redhat.com>,
 *          Andrew Psaltis <ampsaltis@gmail.com>
 */

#include "config.h"
#include "polkitagenthelperprivate.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef HAVE_CLEARENV
extern char **environ;

int
_polkit_clearenv (void)
{
  if (environ != NULL)
    environ[0] = NULL;
  return 0;
}
#else
int
_polkit_clearenv (void)
{
  return clearenv ();
}
#endif


char *
read_cookie (int argc, char **argv)
{
  /* As part of CVE-2015-4625, we started passing the cookie
   * on standard input, to ensure it's not visible to other
   * processes.  However, to ensure that things continue
   * to work if the setuid binary is upgraded while old
   * agents are still running (this will be common with
   * package managers), we support both modes.
   */
  if (argc == 3)
    return strdup (argv[2]);
  else
    {
      char *ret = NULL;
      size_t n = 0;
      ssize_t r = getline (&ret, &n, stdin);
      if (r == -1)
        {
          if (!feof (stdin))
            perror ("getline");
          free (ret);
          return NULL;
        }
      else
        {
          g_strchomp (ret);
          return ret;
        }
    }
}

gboolean
send_dbus_message (const char *cookie, const char *user)
{
  PolkitAuthority *authority = NULL;
  PolkitIdentity *identity = NULL;
  GError *error;
  gboolean ret;

  ret = FALSE;

  error = NULL;
  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_printerr ("Error getting authority: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  identity = polkit_unix_user_new_for_name (user, &error);
  if (identity == NULL)
    {
      g_printerr ("Error constructing identity: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  if (!polkit_authority_authentication_agent_response_sync (authority,
                                                            cookie,
                                                            identity,
                                                            NULL,
                                                            &error))
    {
      g_printerr ("polkit-agent-helper-1: error response to PolicyKit daemon: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  ret = TRUE;

 out:

  if (identity != NULL)
    g_object_unref (identity);

  if (authority != NULL)
    g_object_unref (authority);

  return ret;
}

void
flush_and_wait ()
{
  fflush (stdout);
  fflush (stderr);
#ifdef HAVE_FDATASYNC
  fdatasync (fileno(stdout));
  fdatasync (fileno(stderr));
#else
  fsync (fileno(stdout));
  fsync (fileno(stderr));
#endif
  usleep (100 * 1000);
}

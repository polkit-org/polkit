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


gboolean
send_dbus_message (const char *cookie, const char *user)
{
  PolkitAuthority *authority = NULL;
  PolkitIdentity *identity = NULL;
  GError *error;
  gboolean ret;

  ret = FALSE;

  g_type_init ();

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
  fdatasync (fileno(stdout));
  fdatasync (fileno(stderr));
  usleep (100 * 1000);
}

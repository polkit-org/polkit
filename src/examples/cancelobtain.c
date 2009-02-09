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

/* Simple example that shows how to obtain an authorization including
 * cancelling the request.
 */

#include <polkit/polkit.h>

static void
obtain_authorization_cb (PolkitAuthority *authority,
                         GAsyncResult    *res,
                         GMainLoop       *loop)
{
  GError *error;

  error = NULL;
  if (!polkit_authority_obtain_authorization_finish (authority, res, &error))
    {
      g_print ("Error obtaining authorization: %s\n", error->message);
      g_error_free (error);
    }

  g_main_loop_quit (loop);
}

static gboolean
do_cancel (GCancellable *cancellable)
{
  g_print ("Timer has expired; cancelling request\n");
  g_cancellable_cancel (cancellable);
  return FALSE;
}

int
main (int argc, char *argv[])
{
  int ret;
  GMainLoop *loop;
  PolkitSubject *calling_process;
  PolkitAuthority *authority;
  GCancellable *cancellable;

  g_type_init ();

  ret = 1;

  if (argc != 2)
    {
      g_printerr ("usage: cancelobtain <actionid>\n");
      goto out;
    }

  loop = g_main_loop_new (NULL, FALSE);

  authority = polkit_authority_get ();

  calling_process = polkit_unix_process_new (getppid ());

  cancellable = g_cancellable_new ();

  g_print ("Will cancel request in 10 seconds\n");
  g_timeout_add (10 * 1000,
                 (GSourceFunc) do_cancel,
                 cancellable);

  polkit_authority_obtain_authorization (authority,
                                         calling_process,
                                         argv[1],
                                         cancellable,
                                         (GAsyncReadyCallback) obtain_authorization_cb,
                                         loop);

  g_main_loop_run (loop);

  g_object_unref (authority);
  g_object_unref (calling_process);
  g_object_unref (cancellable);
  g_main_loop_unref (loop);

  ret = 0;

 out:

  return ret;
}

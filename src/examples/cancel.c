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

/* Simple example that shows how to check for an authorization
 * including cancelling the check.
 *
 * Cancelling an authorization check is desirable in situations where
 * the object/action to check for vanishes.
 *
 * One concrete example of this is a disks service in which the user
 * needs to authenticate to modify a disk. If the disk is removed
 * while the authentication dialog is shown, the disks service should
 * cancel the authorization check. A side effect of this, is that the
 * authentication dialog is removed.
 */

#include "config.h"
#include <polkit/polkit.h>

static gboolean
on_tensec_timeout (gpointer user_data)
{
  GMainLoop *loop = user_data;
  g_print ("Ten seconds has passed. Now exiting.\n");
  g_main_loop_quit (loop);
  return FALSE;
}

static void
check_authorization_cb (PolkitAuthority *authority,
                        GAsyncResult    *res,
                        gpointer         user_data)
{
  GMainLoop *loop = user_data;
  PolkitAuthorizationResult *result;
  GError *error;

  error = NULL;
  result = polkit_authority_check_authorization_finish (authority, res, &error);
  if (error != NULL)
    {
      g_print ("Error checking authorization: %s\n", error->message);
      g_error_free (error);
    }
  else
    {
      const gchar *result_str;
      if (polkit_authorization_result_get_is_authorized (result))
        {
          result_str = "authorized";
        }
      else if (polkit_authorization_result_get_is_challenge (result))
        {
          result_str = "challenge";
        }
      else
        {
          result_str = "not authorized";
        }

      g_print ("Authorization result: %s\n", result_str);
    }

  g_print ("Authorization check has been cancelled and the dialog should now be hidden.\n"
           "This process will exit in ten seconds.\n");
  g_timeout_add (10000, on_tensec_timeout, loop);
}

static gboolean
do_cancel (GCancellable *cancellable)
{
  g_print ("Timer has expired; cancelling authorization check\n");
  g_cancellable_cancel (cancellable);
  return FALSE;
}

int
main (int argc, char *argv[])
{
  pid_t parent_pid;
  const gchar *action_id;
  GMainLoop *loop;
  PolkitSubject *subject;
  PolkitAuthority *authority;
  GCancellable *cancellable;

  if (argc != 2)
    {
      g_printerr ("usage: %s <action_id>\n", argv[0]);
      return 1;
    }
  action_id = argv[1];

  loop = g_main_loop_new (NULL, FALSE);

  authority = polkit_authority_get_sync (NULL, NULL);

  /* Typically mechanisms will use a PolkitSystemBusName since most
   * clients communicate with the mechanism via D-Bus. However for
   * this simple example we use the process id of the calling process.
   *
   * Note that if the parent was reaped we have to be careful not to
   * check if init(1) is authorized (it always is).
   */
  parent_pid = getppid ();
  if (parent_pid == 1)
    {
      g_printerr ("Parent process was reaped by init(1)\n");
      return 1;
    }
  subject = polkit_unix_process_new_for_owner (parent_pid, 0, getuid ());

  cancellable = g_cancellable_new ();

  g_print ("Will cancel authorization check in 10 seconds\n");

  /* Set up a 10 second timer to cancel the check */
  g_timeout_add (10 * 1000,
                 (GSourceFunc) do_cancel,
                 cancellable);

  polkit_authority_check_authorization (authority,
                                        subject,
                                        action_id,
                                        NULL, /* PolkitDetails */
                                        POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                        cancellable,
                                        (GAsyncReadyCallback) check_authorization_cb,
                                        loop);

  g_main_loop_run (loop);

  g_object_unref (authority);
  g_object_unref (subject);
  g_object_unref (cancellable);
  g_main_loop_unref (loop);

  return 0;
}

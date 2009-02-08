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

/* Simple example that shows how to check for an authorization including
 * cancelling the check.
 *
 * Cancelling an authorization check is desirable in situations where the
 * object/action to check for vanishes. One concrete example of this is
 * a disks daemon in which the user needs to authenticate to mount a file
 * system. If the disk is removed while the user is busy with the authentication
 * dialog, the disks daemon should cancel the authorization check.
 */

#include <polkit/polkit.h>

static void
check_authorization_cb (PolkitAuthority *authority,
                        GAsyncResult    *res,
                        GMainLoop       *loop)
{
  GError *error;
  PolkitAuthorizationResult result;

  error = NULL;
  result = polkit_authority_check_authorization_finish (authority, res, &error);
  if (error != NULL)
    {
      g_print ("Error checking authorization: %s\n", error->message);
      g_error_free (error);
    }
  else
    {
      gchar *result_str;
      switch (result)
        {
        case POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED:
          result_str = g_strdup ("POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED");
          break;

        case POLKIT_AUTHORIZATION_RESULT_AUTHORIZED:
          result_str = g_strdup ("POLKIT_AUTHORIZATION_RESULT_AUTHORIZED");
          break;

        case POLKIT_AUTHORIZATION_RESULT_CHALLENGE:
          result_str = g_strdup ("POLKIT_AUTHORIZATION_RESULT_CHALLENGE");
          break;

        default:
          result_str = g_strdup_printf ("Unknown return code %d", result);
          break;
        }
      g_print ("Authorization result: %s\n", result_str);
      g_free (result_str);
    }

  g_main_loop_quit (loop);
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
  GMainLoop *loop;
  PolkitSubject *calling_process;
  PolkitAuthority *authority;
  GCancellable *cancellable;

  g_type_init ();

  loop = g_main_loop_new (NULL, FALSE);

  authority = polkit_authority_get ();

  calling_process = polkit_unix_process_new (getppid ());

  cancellable = g_cancellable_new ();

  g_print ("Will cancel authorization check in 10 seconds\n");
  g_timeout_add (10 * 1000,
                 (GSourceFunc) do_cancel,
                 cancellable);

  polkit_authority_check_authorization (authority,
                                        calling_process,
                                        "org.freedesktop.policykit.grant",
                                        POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                        cancellable,
                                        (GAsyncReadyCallback) check_authorization_cb,
                                        loop);

  g_main_loop_run (loop);

  g_object_unref (authority);
  g_object_unref (calling_process);
  g_object_unref (cancellable);
  g_main_loop_unref (loop);

  return 0;
}

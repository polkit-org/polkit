/*
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2009-2010 Andrew Psaltis <ampsaltis@gmail.com>
 * Copyright (C) 2010 Antoine Jacoutot <ajacoutot@openbsd.org>
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
 * Authors: Andrew Psaltis <ampsaltis@gmail.com>, based on
 *            polkitagenthelper.c which was written by
 *          David Zeuthen <davidz@redhat.com>
 */

#include "polkitagenthelperprivate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <syslog.h>
#include <pwd.h>
#include <login_cap.h>
#include <bsd_auth.h>

#include <polkit/polkit.h>

static gboolean bsdauth_authenticate (const char *user_to_auth);

int
main (int argc, char *argv[])
{
  struct passwd *pw;
  const char *user_to_auth;
  char *cookie = NULL;

  /* clear the entire environment to avoid attacks with
     libraries honoring environment variables */
  if (_polkit_clearenv () != 0)
    goto error;

  /* set a minimal environment */
  setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

  /* check that we are setuid root */
  if (geteuid () != 0)
    {
      fprintf (stderr, "polkit-agent-helper-1: needs to be setuid root\n");
      goto error;
    }

  openlog ("polkit-agent-helper-1", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

  /* check for correct invocation */
  if (!(argc == 2 || argc == 3))
    {
      syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
      fprintf (stderr, "polkit-agent-helper-1: wrong number of arguments. This incident has been logged.\n");
      goto error;
    }

  if (getuid () != 0)
    {
    /* check we're running with a non-tty stdin */
    if (isatty (STDIN_FILENO) != 0)
      {
        syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
        fprintf (stderr, "polkit-agent-helper-1: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
        goto error;
      }
    }

  user_to_auth = argv[1];
  cookie = read_cookie (argc, argv);
  if (!cookie)
    goto error;

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: user to auth is '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

  /* Search the password database for the user requesting authentication */
  if ((pw = getpwnam (user_to_auth)) == NULL)
    {
      syslog (LOG_NOTICE, "password database information request for user %s [uid=%d] failed", user_to_auth, getuid());
      fprintf(stderr, "polkit-agent-helper-1: could not get user information for '%s'", user_to_auth);
      goto error;
    }

  /* Check the user's identity */
  if (!bsdauth_authenticate (user_to_auth))
    {
      syslog (LOG_NOTICE, "authentication failure [uid=%d] trying to authenticate '%s'", getuid (), user_to_auth);
      fprintf (stderr, "polkit-agent-helper-1: authentication failure. This incident has been logged.\n");
      goto error;
    }

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: sending D-Bus message to polkit daemon\n");
#endif /* PAH_DEBUG */

  /* now send a D-Bus message to the polkit daemon that
   * includes a) the cookie; and b) the user we authenticated
   */
  if (!send_dbus_message (cookie, user_to_auth))
    {
#ifdef PAH_DEBUG
      fprintf (stderr, "polkit-agent-helper-1: error sending D-Bus message to polkit daemon\n");
#endif /* PAH_DEBUG */
      goto error;
    }

  free (cookie);

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully sent D-Bus message to polkit daemon\n");
#endif /* PAH_DEBUG */

  fprintf (stdout, "SUCCESS\n");
  flush_and_wait ();
  return 0;

error:
  free (cookie);
  fprintf (stdout, "FAILURE\n");
  flush_and_wait ();
  return 1;
}

static gboolean
bsdauth_authenticate (const char *user_to_auth)
{
  char passwd[512];

  fprintf (stdout, "PAM_PROMPT_ECHO_OFF password:\n");
  fflush (stdout);
  usleep (10 * 1000); /* since fflush(3) seems buggy */

  if (fgets (passwd, sizeof (passwd), stdin) == NULL)
    goto error;

  if (strlen (passwd) > 0 && passwd[strlen (passwd) - 1] == '\n')
    passwd[strlen (passwd) - 1] = '\0';

  if (auth_userokay((char *)user_to_auth, NULL, "auth-polkit", passwd) == 0)
    goto error;
  return 1;
error:
  return 0;
}

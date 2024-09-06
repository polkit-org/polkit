/*
 * Copyright (C) 2008, 2010 Red Hat, Inc.
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

#include "polkitagenthelperprivate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <syslog.h>
#include <security/pam_appl.h>

#include <polkit/polkit.h>

#ifndef SO_PEERPIDFD
#  if defined(__parisc__)
#    define SO_PEERPIDFD 0x404B
#  elif defined(__sparc__)
#    define SO_PEERPIDFD 0x0056
#  else
#    define SO_PEERPIDFD 77
#  endif
#endif

static int conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data);

static void
send_to_helper (const gchar *str1,
                const gchar *str2)
{
  char *escaped;
  char *tmp2;
  size_t len2;

  tmp2 = g_strdup(str2);
  g_assert (tmp2 != NULL);
  len2 = strlen(tmp2);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s ' to stdout\n", str1);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s ", str1);

  if (len2 > 0 && tmp2[len2 - 1] == '\n')
    tmp2[len2 - 1] = '\0';
  escaped = g_strescape (tmp2, NULL);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s' to stdout\n", escaped);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s", escaped);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing newline to stdout\n");
#endif /* PAH_DEBUG */
  fputc ('\n', stdout);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: flushing stdout\n");
#endif /* PAH_DEBUG */
  fflush (stdout);

  g_free (escaped);
  g_free (tmp2);
}

int
main (int argc, char *argv[])
{
  int rc;
  int pidfd = -1;
  int uid = -1;
  const char *user_to_auth;
  char *user_to_auth_free = NULL;
  char *cookie = NULL;
  struct pam_conv pam_conversation;
  pam_handle_t *pam_h;
  const void *authed_user;

  rc = 0;
  pam_h = NULL;

  char *lang = getenv("LANG");
  char *language = getenv("LANGUAGE");

  /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
  if (_polkit_clearenv () != 0)
    goto error;

  /* set a minimal environment */
  setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

  if(lang)
      setenv("LANG",lang,0);
  if(language)
      setenv("LANGUAGE",language,0);

  /* check that we are setuid root */
  if (geteuid () != 0)
    {
      gchar *s;

      fprintf (stderr, "polkit-agent-helper-1: needs to be setuid root\n");

      /* Special-case a very common error triggered in jhbuild setups */
      s = g_strdup_printf ("Incorrect permissions on %s (needs to be setuid root)", argv[0]);
      send_to_helper ("PAM_ERROR_MSG", s);
      g_free (s);
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

  /* We are socket activated and the socket has been set up as stdio/stdout, read user from it */
  if (argv[1] != NULL && strcmp (argv[1], "--socket-activated") == 0)
    {
      socklen_t socklen = sizeof(int);
      struct ucred ucred;

      user_to_auth_free = read_cookie (argc, argv);
      if (!user_to_auth_free)
        goto error;
      user_to_auth = user_to_auth_free;

      rc = getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen);
      if (rc < 0)
        {
          if (errno == ENOPROTOOPT || errno == ENODATA)
            {
              syslog (LOG_ERR, "Pidfd not supported on this platform, disable polkit-agent-helper.socket and use setuid helper");
              fprintf (stderr, "polkit-agent-helper-1: pidfd not supported on this platform, disable polkit-agent-helper.socket and use setuid helper.\n");
            }
          if (errno == EINVAL)
            {
              syslog (LOG_ERR, "Caller already exited, unable to get pidfd");
              fprintf (stderr, "polkit-agent-helper-1: caller already exited, unable to get pidfd.\n");
            }

          goto error;
        }

      socklen = sizeof(ucred);
      rc = getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
      if (rc < 0)
        {
          syslog (LOG_ERR, "Unable to get credentials from socket");
          fprintf (stderr, "polkit-agent-helper-1: unable to get credentials from socket.\n");
          goto error;
        }

      uid = ucred.uid;
    }
  else
    user_to_auth = argv[1];

  cookie = read_cookie (argc, argv);
  if (!cookie)
    goto error;

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

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: user to auth is '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

  pam_conversation.conv        = conversation_function;
  pam_conversation.appdata_ptr = NULL;

  /* start the pam stack */
  rc = pam_start ("polkit-1",
                  user_to_auth,
                  &pam_conversation,
                  &pam_h);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_start failed: %s\n", pam_strerror (pam_h, rc));
      goto error;
    }

  /* set the requesting user */
  rc = pam_set_item (pam_h, PAM_RUSER, user_to_auth);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_set_item failed: %s\n", pam_strerror (pam_h, rc));
      goto error;
    }

  /* is user really user? */
  rc = pam_authenticate (pam_h, 0);
  if (rc != PAM_SUCCESS)
    {
      const char *err;
      err = pam_strerror (pam_h, rc);
      fprintf (stderr, "polkit-agent-helper-1: pam_authenticate failed: %s\n", err);
      goto error;
    }

  /* permitted access? */
  rc = pam_acct_mgmt (pam_h, 0);
  if (rc != PAM_SUCCESS)
    {
      const char *err;
      err = pam_strerror (pam_h, rc);
      fprintf (stderr, "polkit-agent-helper-1: pam_acct_mgmt failed: %s\n", err);
      goto error;
    }

  /* did we auth the right user? */
  rc = pam_get_item (pam_h, PAM_USER, &authed_user);
  if (rc != PAM_SUCCESS)
    {
      const char *err;
      err = pam_strerror (pam_h, rc);
      fprintf (stderr, "polkit-agent-helper-1: pam_get_item failed: %s\n", err);
      goto error;
    }

  if (strcmp (authed_user, user_to_auth) != 0)
    {
      fprintf (stderr, "polkit-agent-helper-1: Tried to auth user '%s' but we got auth for user '%s' instead",
               user_to_auth, (const char *) authed_user);
      goto error;
    }

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully authenticated user '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

  pam_end (pam_h, rc);
  pam_h = NULL;

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  /* now send a D-Bus message to the PolicyKit daemon that
   * includes a) the cookie; b) the user we authenticated;
   * c) the pidfd and uid of the caller, if socket-activated
   */
  if (!send_dbus_message (cookie, user_to_auth, pidfd, uid))
    {
#ifdef PAH_DEBUG
      fprintf (stderr, "polkit-agent-helper-1: error sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */
      goto error;
    }

  free (cookie);
  free (user_to_auth_free);
  if (pidfd >= 0)
    close (pidfd);

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully sent D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  fprintf (stdout, "SUCCESS\n");
  flush_and_wait();
  return 0;

error:
  free (cookie);
  free (user_to_auth_free);
  if (pidfd >= 0)
    close (pidfd);
  if (pam_h != NULL)
    pam_end (pam_h, rc);

  fprintf (stdout, "FAILURE\n");
  flush_and_wait();
  return 1;
}

static int
conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  char buf[PAM_MAX_RESP_SIZE];
  int i;

  (void)data;
  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return PAM_CONV_ERR;

  if ((aresp = calloc(n, sizeof *aresp)) == NULL)
    return PAM_BUF_ERR;

  for (i = 0; i < n; ++i)
    {
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;
      switch (msg[i]->msg_style)
        {

        case PAM_PROMPT_ECHO_OFF:
          send_to_helper ("PAM_PROMPT_ECHO_OFF", msg[i]->msg);
          goto conv1;

        case PAM_PROMPT_ECHO_ON:
          send_to_helper ("PAM_PROMPT_ECHO_ON", msg[i]->msg);

        conv1:
          if (fgets (buf, sizeof buf, stdin) == NULL)
            goto error;

          if (strlen (buf) > 0 &&
              buf[strlen (buf) - 1] == '\n')
            buf[strlen (buf) - 1] = '\0';

          aresp[i].resp = strdup (buf);
          if (aresp[i].resp == NULL)
            goto error;
          break;

        case PAM_ERROR_MSG:
          send_to_helper ("PAM_ERROR_MSG", msg[i]->msg);
          break;

        case PAM_TEXT_INFO:
          send_to_helper ("PAM_TEXT_INFO", msg[i]->msg);
          break;

        default:
          goto error;
        }
    }

  *resp = aresp;
  return PAM_SUCCESS;

error:

  for (i = 0; i < n; ++i)
    {
      if (aresp[i].resp != NULL) {
        memset (aresp[i].resp, 0, strlen(aresp[i].resp));
        free (aresp[i].resp);
      }
    }
  memset (aresp, 0, n * sizeof *aresp);
  free (aresp);
  *resp = NULL;
  return PAM_CONV_ERR;
}

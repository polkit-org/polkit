/*
 * Copyright (C) 2008 Red Hat, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <security/pam_appl.h>

#ifdef HAVE_SOLARIS
#  define LOG_AUTHPRIV    (10<<3)
#endif

/* Development aid: define PAH_DEBUG to get debugging output. Do _NOT_
 * enable this in production builds; it may leak passwords and other
 * sensitive information.
 */
#undef PAH_DEBUG
#define PAH_DEBUG

static int conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data);

int
main (int argc, char *argv[])
{
  int rc;
  const char *user_to_auth;
  const char *cookie;
  struct pam_conv pam_conversation;
  pam_handle_t *pam_h;
  const void *authed_user;

  rc = 0;
  pam_h = NULL;

  /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
  if (clearenv () != 0)
    goto error;

  /* set a minimal environment */
  setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

  /* check that we are setuid root */
  if (geteuid () != 0)
    {
      fprintf (stderr, "polkit-grant-helper-pam: needs to be setuid root\n");
      goto error;
    }

  openlog ("polkit-agent-helper-1", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

  /* check for correct invocation */
  if (argc != 3)
    {
      syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
      fprintf (stderr, "polkit-agent-helper-1: wrong number of arguments. This incident has been logged.\n");
      goto error;
    }

  user_to_auth = argv[1];
  cookie = argv[2];

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
      fprintf (stderr, "polkit-agent-helper-1: pam_authenticated failed: %s\n", pam_strerror (pam_h, rc));
      goto error;
    }

  /* permitted access? */
  rc = pam_acct_mgmt (pam_h, 0);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_acct_mgmt failed: %s\n", pam_strerror (pam_h, rc));
      goto error;
    }

  /* did we auth the right user? */
  rc = pam_get_item (pam_h, PAM_USER, &authed_user);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_get_item failed: %s\n", pam_strerror (pam_h, rc));
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

  /* TODO: now send a D-Bus message to the PolicyKit daemon that
   *       includes a) the cookie; and b) the user we authenticated
   */

  fprintf (stdout, "SUCCESS\n");
  fflush (stdout);

  pam_end (pam_h, rc);
  return 0;

error:
  if (pam_h != NULL)
    pam_end (pam_h, rc);

  fprintf (stdout, "FAILURE\n");
  fflush (stdout);
  return 1;
}

static int
conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  char buf[PAM_MAX_RESP_SIZE];
  int i;

  data = data;
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
          fprintf (stdout, "PAM_PROMPT_ECHO_OFF ");
          goto conv1;

        case PAM_PROMPT_ECHO_ON:
          fprintf (stdout, "PAM_PROMPT_ECHO_ON ");
        conv1:
          fputs (msg[i]->msg, stdout);
          if (strlen (msg[i]->msg) > 0 && msg[i]->msg[strlen (msg[i]->msg) - 1] != '\n')
            fputc ('\n', stdout);
          fflush (stdout);

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
          fprintf (stdout, "PAM_ERROR_MSG ");
          goto conv2;

        case PAM_TEXT_INFO:
          fprintf (stdout, "PAM_TEXT_INFO ");
        conv2:
          fputs (msg[i]->msg, stdout);
          if (strlen (msg[i]->msg) > 0 &&
              msg[i]->msg[strlen (msg[i]->msg) - 1] != '\n')
            fputc ('\n', stdout);
          fflush (stdout);
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
  *resp = NULL;
  return PAM_CONV_ERR;
}

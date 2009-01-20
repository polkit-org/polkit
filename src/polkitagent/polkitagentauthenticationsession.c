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

/* TODO: This whole class needs to be rewritten so it uses the main loop etc. etc.
 *
 *       And we REALLY REALLY really really should use signals instead of callbacks...
 */


/* for getline(), see below */
#define _GNU_SOURCE

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include "polkitagentauthenticationsession.h"

struct _PolkitAgentAuthenticationSession
{
  GObject parent_instance;

  gchar *cookie;
  PolkitIdentity *identity;

  int child_stdin;
  int child_stdout;
  GPid child_pid;
  FILE *child_stdout_f;

  int child_watch_id;
  int io_watch_id;

  gboolean success;
  gboolean helper_is_running;

  PolkitAgentAuthenticationSessionConversationPromptEchoOff func_prompt_echo_off;
  PolkitAgentAuthenticationSessionConversationPromptEchoOn func_prompt_echo_on;
  PolkitAgentAuthenticationSessionConversationErrorMessage func_error_message;
  PolkitAgentAuthenticationSessionConversationTextInfo func_text_info;
  PolkitAgentAuthenticationSessionDone func_done;
  void *user_data;
};

struct _PolkitAgentAuthenticationSessionClass
{
  GObjectClass parent_class;

};

G_DEFINE_TYPE (PolkitAgentAuthenticationSession, polkit_agent_authentication_session, G_TYPE_OBJECT);

static void
polkit_agent_authentication_session_init (PolkitAgentAuthenticationSession *session)
{
}

static void
polkit_agent_authentication_session_finalize (GObject *object)
{
  PolkitAgentAuthenticationSession *session;

  session = POLKIT_AGENT_AUTHENTICATION_SESSION (object);

  g_free (session->cookie);
  if (session->identity != NULL)
    g_object_unref (session->identity);

  if (G_OBJECT_CLASS (polkit_agent_authentication_session_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_agent_authentication_session_parent_class)->finalize (object);
}

static void
polkit_agent_authentication_session_class_init (PolkitAgentAuthenticationSessionClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_agent_authentication_session_finalize;



}

PolkitAgentAuthenticationSession *
polkit_agent_authentication_session_new (PolkitIdentity *identity,
                                 const gchar    *cookie)
{
  PolkitAgentAuthenticationSession *session;

  session = POLKIT_AGENT_AUTHENTICATION_SESSION (g_object_new (POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION, NULL));

  session->identity = g_object_ref (identity);
  session->cookie = g_strdup (cookie);

  return session;
}

void
polkit_agent_authentication_session_set_functions (PolkitAgentAuthenticationSession *session,
                                           PolkitAgentAuthenticationSessionConversationPromptEchoOff func_prompt_echo_off,
                                           PolkitAgentAuthenticationSessionConversationPromptEchoOn func_prompt_echo_on,
                                           PolkitAgentAuthenticationSessionConversationErrorMessage func_error_message,
                                           PolkitAgentAuthenticationSessionConversationTextInfo func_text_info,
                                           PolkitAgentAuthenticationSessionDone func_done,
                                           void *user_data)
{
  session->func_prompt_echo_off = func_prompt_echo_off;
  session->func_prompt_echo_on = func_prompt_echo_on;
  session->func_error_message = func_error_message;
  session->func_text_info = func_text_info;
  session->func_done = func_done;
  session->user_data = user_data;
}

static void
child_watch_func (GPid pid, gint status, gpointer user_data)
{
  PolkitAgentAuthenticationSession *session = POLKIT_AGENT_AUTHENTICATION_SESSION (user_data);
  gint exit_code;
  gboolean input_was_bogus;

  g_return_if_fail (session->helper_is_running);

  exit_code = WEXITSTATUS (status);

  g_debug ("pid %d terminated", pid);
  waitpid (pid, &status, 0);

  if (exit_code >= 2)
    input_was_bogus = TRUE;
  else
    input_was_bogus = FALSE;

  session->success = (exit_code == 0);
  session->helper_is_running = FALSE;
  session->func_done (session, session->success, input_was_bogus, session->user_data);
}

static gboolean
io_watch_have_data (GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
  PolkitAgentAuthenticationSession *session = POLKIT_AGENT_AUTHENTICATION_SESSION (user_data);
  char *line;
  size_t line_len;
  gchar *id;
  size_t id_len;
  gchar *response;
  gchar *response_prefix;
  int fd;

  g_return_val_if_fail (session->helper_is_running, FALSE);

  fd = g_io_channel_unix_get_fd (channel);

  line = NULL;
  line_len = 0;

  /* TODO: getline is GNU only, see kit_getline() in old polkit */
  while (getline (&line, &line_len, session->child_stdout_f) != -1)
    {
      if (strlen (line) > 0 && line[strlen (line) - 1] == '\n')
        line[strlen (line) - 1] = '\0';

      response = NULL;
      response_prefix = NULL;

      id = "PAM_PROMPT_ECHO_OFF ";
      if (g_str_has_prefix (line, id))
        {
          id_len = strlen (id);
          response_prefix = "";
          response = session->func_prompt_echo_off (session,
                                                  line + id_len,
                                                  session->user_data);
          goto processed;
        }

      id = "PAM_PROMPT_ECHO_ON ";
      if (g_str_has_prefix (line, id))
        {
          id_len = strlen (id);
          response_prefix = "";
          response = session->func_prompt_echo_on (session,
                                                 line + id_len,
                                                 session->user_data);
          goto processed;
        }

      id = "PAM_ERROR_MSG ";
      if (g_str_has_prefix (line, id))
        {
          id_len = strlen (id);
          session->func_error_message (session,
                                     line + id_len,
                                     session->user_data);
          goto processed;
        }

      id = "PAM_TEXT_INFO ";
      if (g_str_has_prefix (line, id))
        {
          id_len = strlen (id);
          session->func_text_info (session,
                                 line + id_len,
                                 session->user_data);
          goto processed;
        }

    processed:
      if (response != NULL && response_prefix != NULL)
        {
          char *buf;
          gboolean add_newline;

          /* add a newline if there isn't one already... */
          add_newline = FALSE;
          if (response[strlen (response) - 1] != '\n')
            {
              add_newline = TRUE;
            }
          buf = g_strdup_printf ("%s%s%c",
                                 response_prefix,
                                 response,
                                 add_newline ? '\n' : '\0');
          write (session->child_stdin, buf, strlen (buf));
          g_free (buf);
          g_free (response);
        }
    }

  if (line != NULL)
    free (line);

  return FALSE;
}

gboolean
polkit_agent_authentication_session_initiate_auth (PolkitAgentAuthenticationSession *session)
{
  uid_t uid;
  GError *error;
  gchar *helper_argv[4];
  GIOChannel *channel;
  gboolean ret;
  struct passwd *passwd;

  ret = FALSE;

  /* TODO: also support authorization for other kinds of identities */
  if (!POLKIT_IS_UNIX_USER (session->identity))
    {
      g_warning ("Unsupported identity type");
      goto error;
    }

  uid = polkit_unix_user_get_uid (POLKIT_UNIX_USER (session->identity));

  passwd = getpwuid (uid);
  if (passwd == NULL)
    {
      g_warning ("No user with uid %d", uid);
      goto error;
    }

  helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-session-helper-1";
  helper_argv[1] = passwd->pw_name;
  helper_argv[2] = session->cookie;
  helper_argv[3] = NULL;

  session->child_stdin = -1;
  session->child_stdout = -1;

  error = NULL;
  if (!g_spawn_async_with_pipes (NULL,
                                 (char **) helper_argv,
                                 NULL,
                                 G_SPAWN_DO_NOT_REAP_CHILD |
                                 0,//G_SPAWN_STDERR_TO_DEV_NULL,
                                 NULL,
                                 NULL,
                                 &session->child_pid,
                                 &session->child_stdin,
                                 &session->child_stdout,
                                 NULL,
                                 &error))
    {
      g_warning ("Cannot spawn helper: %s\n", error->message);
      g_error_free (error);
      goto error;
    }

  session->child_watch_id = g_child_watch_add (session->child_pid, child_watch_func, session);

  channel = g_io_channel_unix_new (session->child_stdout);
  session->io_watch_id = g_io_add_watch (channel, G_IO_IN, io_watch_have_data, session);
  g_io_channel_unref (channel);

  /* so we can use getline... */
  session->child_stdout_f = fdopen (session->child_stdout, "r");

  session->success = FALSE;

  session->helper_is_running = TRUE;

  ret = TRUE;

error:

  return ret;
}


void
polkit_agent_authentication_session_cancel (PolkitAgentAuthenticationSession *session)
{
  GPid pid;

  g_return_if_fail (session->helper_is_running);

  pid = session->child_pid;
  session->child_pid = 0;
  if (pid > 0)
    {
      int status;
      kill (pid, SIGTERM);
      waitpid (pid, &status, 0);
      session->helper_is_running = FALSE;
    }
  session->func_done (session, FALSE, FALSE, session->user_data);
}

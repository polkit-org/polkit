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

/**
 * SECTION:polkitagentsession
 * @title: PolkitAgentSession
 * @short_description: Authentication Session
 *
 * The #PolkitAgentSession class is an abstraction used for interacting with the
 * native authentication system (for example PAM) for obtaining authorizations.
 * This class is typically used together with instances that are derived from
 * the #PolkitAgentListener abstract base class.
 *
 * To perform the actual authentication, #PolkitAgentSession uses a trusted suid helper.
 * The authentication conversation is done through a pipe. This is transparent; the user
 * only need to handle the
 * #PolkitAgentSession::request,
 * #PolkitAgentSession::show-info,
 * #PolkitAgentSession::show-error and
 * #PolkitAgentSession::completed
 * signals and invoke polkit_agent_session_response() in response to requests.
 *
 * If the user successfully authenticates, the authentication helper will invoke
 * a method on the PolicyKit daemon (see polkit_authority_authentication_agent_response_sync())
 * with the given @cookie. Upon receiving a positive response from the PolicyKit daemon (via
 * the authentication helper), the #PolkitAgentSession::completed signal will be emitted
 * with the @gained_authorization paramter set to %TRUE.
 *
 * If the user is unable to authenticate, the #PolkitAgentSession::completed signal will
 * be emitted with the @gained_authorization paramter set to %FALSE.
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include "polkitagentmarshal.h"
#include "polkitagentsession.h"

/**
 * PolkitAgentSession:
 *
 * The #PolkitAgentSession struct should not be accessed directly.
 */
struct _PolkitAgentSession
{
  /*< private >*/

  GObject parent_instance;

  gchar *cookie;
  PolkitIdentity *identity;

  int child_stdin;
  int child_stdout;
  GPid child_pid;

  int child_watch_id;
  int child_stdout_watch_id;
  GIOChannel *child_stdout_channel;

  gboolean success;
  gboolean helper_is_running;
};

struct _PolkitAgentSessionClass
{
  GObjectClass parent_class;

};

enum
{
  REQUEST_SIGNAL,
  SHOW_INFO_SIGNAL,
  SHOW_ERROR_SIGNAL,
  COMPLETED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (PolkitAgentSession, polkit_agent_session, G_TYPE_OBJECT);

static void
polkit_agent_session_init (PolkitAgentSession *session)
{
}

static void kill_helper (PolkitAgentSession *session);

static void
polkit_agent_session_finalize (GObject *object)
{
  PolkitAgentSession *session;

  session = POLKIT_AGENT_SESSION (object);

  /* this releases resources related to the helper */
  kill_helper (session);

  g_free (session->cookie);
  if (session->identity != NULL)
    g_object_unref (session->identity);

  if (G_OBJECT_CLASS (polkit_agent_session_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_agent_session_parent_class)->finalize (object);
}

static void
polkit_agent_session_class_init (PolkitAgentSessionClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_agent_session_finalize;

  /**
   * PolkitAgentSession::request:
   * @session: A #PolkitAgentSession.
   * @request: The request to show the user, e.g. "name: " or "password: ".
   * @echo_on: %TRUE if the response to the request SHOULD be echoed on the
   *           screen, %FALSE if the response MUST NOT be echoed to the screen.
   *
   * Emitted when the user is requested to answer a question.
   *
   * When the response has been collected from the user, call polkit_agent_session_response().
   */
  signals[REQUEST_SIGNAL] = g_signal_new ("request",
                                          POLKIT_AGENT_TYPE_SESSION,
                                          G_SIGNAL_RUN_LAST,
                                          0,                      /* class offset     */
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          polkit_agent_marshal_VOID__STRING_BOOLEAN,
                                          G_TYPE_NONE,
                                          2,
                                          G_TYPE_STRING,
                                          G_TYPE_BOOLEAN);

  /**
   * PolkitAgentSession::show-info:
   * @session: A #PolkitAgentSession.
   * @text: A string to display to the user.
   *
   * Emitted when there is information to be displayed to the user.
   */
  signals[SHOW_INFO_SIGNAL] = g_signal_new ("show-info",
                                            POLKIT_AGENT_TYPE_SESSION,
                                            G_SIGNAL_RUN_LAST,
                                            0,                      /* class offset     */
                                            NULL,                   /* accumulator      */
                                            NULL,                   /* accumulator data */
                                            g_cclosure_marshal_VOID__STRING,
                                            G_TYPE_NONE,
                                            1,
                                            G_TYPE_STRING);

  /**
   * PolkitAgentSession::show-error:
   * @session: A #PolkitAgentSession.
   * @text: An error string to display to the user.
   *
   * Emitted when there is information related to an error condition to be displayed to the user.
   */
  signals[SHOW_ERROR_SIGNAL] = g_signal_new ("show-error",
                                             POLKIT_AGENT_TYPE_SESSION,
                                             G_SIGNAL_RUN_LAST,
                                             0,                      /* class offset     */
                                             NULL,                   /* accumulator      */
                                             NULL,                   /* accumulator data */
                                             g_cclosure_marshal_VOID__STRING,
                                             G_TYPE_NONE,
                                             1,
                                             G_TYPE_STRING);

  /**
   * PolkitAgentSession::completed:
   * @session: A #PolkitAgentSession.
   * @gained_authorization: %TRUE only if the authorization was successfully obtained.
   *
   * Emitted when the authentication session has been completed or
   * cancelled. The @gained_authorization parameter is %TRUE only if
   * the user successfully authenticated.
   *
   * Upon receiving this signal, the user should free @session using g_object_unref().
   */
  signals[COMPLETED_SIGNAL] = g_signal_new ("completed",
                                            POLKIT_AGENT_TYPE_SESSION,
                                            G_SIGNAL_RUN_LAST,
                                            0,                      /* class offset     */
                                            NULL,                   /* accumulator      */
                                            NULL,                   /* accumulator data */
                                            g_cclosure_marshal_VOID__BOOLEAN,
                                            G_TYPE_NONE,
                                            1,
                                            G_TYPE_BOOLEAN);
}

/**
 * polkit_agent_session_new:
 * @identity: The identity to authenticate.
 * @cookie: The cookie obtained from the PolicyKit daemon
 *
 * Creates a new authentication session.
 *
 * The caller should connect to the
 * #PolkitAgentSession::request,
 * #PolkitAgentSession::show-info,
 * #PolkitAgentSession::show-error and
 * #PolkitAgentSession::completed
 * signals and then call polkit_agent_session_initiate() to initiate the authentication session.
 *
 * Returns: A #PolkitAgentSession. Free with g_object_unref().
 **/
PolkitAgentSession *
polkit_agent_session_new (PolkitIdentity *identity,
                          const gchar    *cookie)
{
  PolkitAgentSession *session;

  session = POLKIT_AGENT_SESSION (g_object_new (POLKIT_AGENT_TYPE_SESSION, NULL));

  session->identity = g_object_ref (identity);
  session->cookie = g_strdup (cookie);

  return session;
}

static void
kill_helper (PolkitAgentSession *session)
{
  if (!session->helper_is_running)
    goto out;

  if (session->child_pid > 0)
    {
      gint status;
      //g_debug ("Sending SIGTERM to helper");
      kill (session->child_pid, SIGTERM);
      waitpid (session->child_pid, &status, 0);
      session->child_pid = 0;
    }

  if (session->child_watch_id > 0)
    {
      g_source_remove (session->child_watch_id);
      session->child_watch_id = 0;
    }

  if (session->child_stdout_watch_id > 0)
    {
      g_source_remove (session->child_stdout_watch_id);
      session->child_stdout_watch_id = 0;
    }

  if (session->child_stdout_channel != NULL)
    {
      g_io_channel_unref (session->child_stdout_channel);
      session->child_stdout_channel = NULL;
    }

  session->helper_is_running = FALSE;

 out:
  ;
}

static void
complete_session (PolkitAgentSession *session,
                  gboolean            result)
{
  kill_helper (session);
  g_signal_emit_by_name (session, "completed", result);
}

static void
child_watch_func (GPid     pid,
                  gint     status,
                  gpointer user_data)
{
  PolkitAgentSession *session = POLKIT_AGENT_SESSION (user_data);

  /* kill all the watches we have set up, except for the child since it has exited already */
  session->child_pid = 0;
  kill_helper (session);
}

static gboolean
io_watch_have_data (GIOChannel    *channel,
                    GIOCondition   condition,
                    gpointer       user_data)
{
  PolkitAgentSession *session = POLKIT_AGENT_SESSION (user_data);
  gchar *line;
  GError *error;

  error = NULL;
  line = NULL;

  if (!session->helper_is_running)
    {
      g_warning ("in io_watch_have_data() but helper is not supposed to be running");

      complete_session (session, FALSE);
      goto out;
    }

  g_io_channel_read_line (channel,
                          &line,
                          NULL,
                          NULL,
                          &error);
  if (error != NULL)
    {
      g_warning ("Error reading line from helper: %s", error->message);
      g_error_free (error);

      complete_session (session, FALSE);
      goto out;
    }

  /* remove terminator */
  if (strlen (line) > 0 && line[strlen (line) - 1] == '\n')
    line[strlen (line) - 1] = '\0';

  //g_debug ("Got '%s' from helper", line);

  if (g_str_has_prefix (line, "PAM_PROMPT_ECHO_OFF "))
    {
      g_signal_emit_by_name (session, "request", line + sizeof "PAM_PROMPT_ECHO_OFF " - 1, FALSE);
    }
  else if (g_str_has_prefix (line, "PAM_PROMPT_ECHO_ON "))
    {
      g_signal_emit_by_name (session, "request", line + sizeof "PAM_PROMPT_ECHO_ON " - 1, TRUE);
    }
  else if (g_str_has_prefix (line, "PAM_ERROR_MSG "))
    {
      g_signal_emit_by_name (session, "show-error", line + sizeof "PAM_ERROR_MSG " - 1);
    }
  else if (g_str_has_prefix (line, "PAM_TEXT_INFO "))
    {
      g_signal_emit_by_name (session, "show-info", line + sizeof "PAM_TEXT_INFO " - 1);
    }
  else if (g_str_has_prefix (line, "PAM_TEXT_INFO "))
    {
      g_signal_emit_by_name (session, "show-info", line + sizeof "PAM_TEXT_INFO " - 1);
    }
  else if (g_str_has_prefix (line, "SUCCESS"))
    {
      complete_session (session, TRUE);
    }
  else if (g_str_has_prefix (line, "FAILURE"))
    {
      complete_session (session, FALSE);
    }
  else
    {
      g_warning ("Unknown line '%s' from helper", line);
      complete_session (session, FALSE);
      goto out;
    }

 out:
  g_free (line);

  /* keep the IOChannel around */
  return TRUE;
}

/**
 * polkit_agent_session_response:
 * @session: A #PolkitAgentSession.
 * @response: Response from the user, typically a password.
 *
 * Function for providing response to requests received
 * via the #PolkitAgentSession::request signal.
 **/
void
polkit_agent_session_response (PolkitAgentSession *session,
                               const gchar        *response)
{
  gboolean add_newline;
  size_t response_len;
  const char newline[] = "\n";

  g_return_if_fail (response != NULL);

  response_len = strlen (response);

  add_newline = (response[response_len] != '\n');

  write (session->child_stdin, response, response_len);
  if (add_newline)
    write (session->child_stdin, newline, 1);
}

/**
 * polkit_agent_session_initiate:
 * @session: A #PolkitAgentSession.
 *
 * Initiates the authentication session.
 *
 * Use polkit_agent_session_cancel() to cancel the session.
 **/
void
polkit_agent_session_initiate (PolkitAgentSession *session)
{
  uid_t uid;
  GError *error;
  gchar *helper_argv[4];
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

  helper_argv[0] = PACKAGE_LIBEXEC_DIR "/polkit-agent-helper-1";
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
  session->child_stdout_channel = g_io_channel_unix_new (session->child_stdout);
  session->child_stdout_watch_id = g_io_add_watch (session->child_stdout_channel, G_IO_IN, io_watch_have_data, session);

  session->success = FALSE;

  session->helper_is_running = TRUE;

  return;

error:
  complete_session (session, FALSE);
}


/**
 * polkit_agent_session_cancel:
 * @session: A #PolkitAgentSession.
 *
 * Cancels an authentication session. This will make @session emit the #PolkitAgentSession::completed
 * signal.
 **/
void
polkit_agent_session_cancel (PolkitAgentSession *session)
{
  complete_session (session, FALSE);
}

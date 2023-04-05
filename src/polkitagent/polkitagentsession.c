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
 * @stability: Unstable
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
#include <gio/gunixoutputstream.h>
#include <pwd.h>

#include "polkitagentmarshal.h"
#include "polkitagentsession.h"

static gboolean
_show_debug (void)
{
  static volatile gsize has_show_debug = 0;
  static gboolean show_debug_value = FALSE;

  if (g_once_init_enter (&has_show_debug))
    {
      show_debug_value = (g_getenv ("POLKIT_DEBUG") != NULL);
      g_once_init_leave (&has_show_debug, 1);
    }
  return show_debug_value;
}

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

  GOutputStream *child_stdin;
  int child_stdout;
  GPid child_pid;

  GSource *child_stdout_watch_source;
  GIOChannel *child_stdout_channel;

  gboolean success;
  gboolean helper_is_running;
  gboolean have_emitted_completed;
};

struct _PolkitAgentSessionClass
{
  GObjectClass parent_class;

};

enum
{
  PROP_0,
  PROP_IDENTITY,
  PROP_COOKIE
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
  session->child_stdout = -1;
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
polkit_agent_session_get_property (GObject     *object,
                                   guint        prop_id,
                                   GValue      *value,
                                   GParamSpec  *pspec)
{
  PolkitAgentSession *session = POLKIT_AGENT_SESSION (object);

  switch (prop_id)
    {
    case PROP_IDENTITY:
      g_value_set_object (value, session->identity);
      break;

    case PROP_COOKIE:
      g_value_set_string (value, session->cookie);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_agent_session_set_property (GObject      *object,
                                   guint         prop_id,
                                   const GValue *value,
                                   GParamSpec   *pspec)
{
  PolkitAgentSession *session = POLKIT_AGENT_SESSION (object);

  switch (prop_id)
    {
    case PROP_IDENTITY:
      session->identity = g_value_dup_object (value);
      break;

    case PROP_COOKIE:
      session->cookie = g_value_dup_string (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_agent_session_class_init (PolkitAgentSessionClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_agent_session_finalize;
  gobject_class->get_property = polkit_agent_session_get_property;
  gobject_class->set_property = polkit_agent_session_set_property;

  /**
   * PolkitAgentSession:identity:
   *
   * The identity to authenticate.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_IDENTITY,
                                   g_param_spec_object ("identity",
                                                        "Identity",
                                                        "The identity to authenticate",
                                                        POLKIT_TYPE_IDENTITY,
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

  /**
   * PolkitAgentSession:cookie:
   *
   * The cookie obtained from the PolicyKit daemon
   */
  g_object_class_install_property (gobject_class,
                                   PROP_COOKIE,
                                   g_param_spec_string ("cookie",
                                                        "Cookie",
                                                        "The cookie obtained from the PolicyKit daemon",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

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
                                          _polkit_agent_marshal_VOID__STRING_BOOLEAN,
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

  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), NULL);
  g_return_val_if_fail (cookie != NULL, NULL);

  session = POLKIT_AGENT_SESSION (g_object_new (POLKIT_AGENT_TYPE_SESSION,
                                                "identity", identity,
                                                "cookie", cookie,
                                                NULL));

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

  if (session->child_stdout_watch_source != NULL)
    {
      g_source_destroy (session->child_stdout_watch_source);
      g_source_unref (session->child_stdout_watch_source);
      session->child_stdout_watch_source = NULL;
    }

  if (session->child_stdout_channel != NULL)
    {
      g_io_channel_unref (session->child_stdout_channel);
      session->child_stdout_channel = NULL;
    }

  if (session->child_stdout != -1)
    {
      g_warn_if_fail (close (session->child_stdout) == 0);
      session->child_stdout = -1;
    }

  g_clear_object (&session->child_stdin);

  session->helper_is_running = FALSE;

 out:
  ;
}

static void
complete_session (PolkitAgentSession *session,
                  gboolean            result)
{
  kill_helper (session);
  if (!session->have_emitted_completed)
    {
      if (G_UNLIKELY (_show_debug ()))
        g_print ("PolkitAgentSession: emitting ::completed(%s)\n", result ? "TRUE" : "FALSE");
      session->have_emitted_completed = TRUE;
      /* Note that the signal handler may drop the last reference to session. */
      g_signal_emit_by_name (session, "completed", result);
    }
}

static gboolean
io_watch_have_data (GIOChannel    *channel,
                    GIOCondition   condition,
                    gpointer       user_data)
{
  PolkitAgentSession *session = POLKIT_AGENT_SESSION (user_data);
  gchar *line, *unescaped;
  GError *error;

  error = NULL;
  line = NULL;
  unescaped = NULL;

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
  if (error != NULL || line == NULL)
    {
      /* In case we get just G_IO_HUP, line is NULL but error is
         unset.*/
      g_warning ("Error reading line from helper: %s",
                 error ? error->message : "nothing to read");
      g_clear_error (&error);

      complete_session (session, FALSE);
      goto out;
    }

  /* remove terminator */
  if (strlen (line) > 0 && line[strlen (line) - 1] == '\n')
    line[strlen (line) - 1] = '\0';

  unescaped = g_strcompress (line);

  if (G_UNLIKELY (_show_debug ()))
    g_print ("PolkitAgentSession: read `%s' from helper\n", unescaped);

  if (g_str_has_prefix (unescaped, "PAM_PROMPT_ECHO_OFF "))
    {
      const gchar *s = unescaped + sizeof "PAM_PROMPT_ECHO_OFF " - 1;
      if (G_UNLIKELY (_show_debug ()))
        g_print ("PolkitAgentSession: emitting ::request('%s', FALSE)\n", s);
      g_signal_emit_by_name (session, "request", s, FALSE);
    }
  else if (g_str_has_prefix (unescaped, "PAM_PROMPT_ECHO_ON "))
    {
      const gchar *s = unescaped + sizeof "PAM_PROMPT_ECHO_ON " - 1;
      if (G_UNLIKELY (_show_debug ()))
        g_print ("PolkitAgentSession: emitting ::request('%s', TRUE)\n", s);
      g_signal_emit_by_name (session, "request", s, TRUE);
    }
  else if (g_str_has_prefix (unescaped, "PAM_ERROR_MSG "))
    {
      const gchar *s = unescaped + sizeof "PAM_ERROR_MSG " - 1;
      if (G_UNLIKELY (_show_debug ()))
        g_print ("PolkitAgentSession: emitting ::show-error('%s')\n", s);
      g_signal_emit_by_name (session, "show-error", s);
    }
  else if (g_str_has_prefix (unescaped, "PAM_TEXT_INFO "))
    {
      const gchar *s = unescaped + sizeof "PAM_TEXT_INFO " - 1;
      if (G_UNLIKELY (_show_debug ()))
        g_print ("PolkitAgentSession: emitting ::show-info('%s')\n", s);
      g_signal_emit_by_name (session, "show-info", s);
    }
  else if (g_str_has_prefix (unescaped, "SUCCESS"))
    {
      complete_session (session, TRUE);
    }
  else if (g_str_has_prefix (unescaped, "FAILURE"))
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
  g_free (unescaped);

  if (condition & (G_IO_ERR | G_IO_HUP))
    complete_session (session, FALSE);

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

  g_return_if_fail (POLKIT_AGENT_IS_SESSION (session));
  g_return_if_fail (response != NULL);

  response_len = strlen (response);

  add_newline = (response_len == 0 || response[response_len - 1] != '\n');

  (void) g_output_stream_write_all (session->child_stdin, response, response_len, NULL, NULL, NULL);
  if (add_newline)
    (void) g_output_stream_write_all (session->child_stdin, newline, 1, NULL, NULL, NULL);
}

/**
 * polkit_agent_session_initiate:
 * @session: A #PolkitAgentSession.
 *
 * Initiates the authentication session. Before calling this method,
 * make sure to connect to the various signals. The signals will be
 * emitted in the <link
 * linkend="g-main-context-push-thread-default">thread-default main
 * loop</link> that this method is invoked from.
 *
 * Use polkit_agent_session_cancel() to cancel the session.
 **/
void
polkit_agent_session_initiate (PolkitAgentSession *session)
{
  uid_t uid;
  GError *error;
  gchar *helper_argv[3];
  struct passwd *passwd;
  int stdin_fd = -1;

  g_return_if_fail (POLKIT_AGENT_IS_SESSION (session));

  if (G_UNLIKELY (_show_debug ()))
    {
      gchar *s;
      s = polkit_identity_to_string (session->identity);
      g_print ("PolkitAgentSession: initiating authentication for identity `%s', cookie %s\n",
               s,
               session->cookie);
      g_free (s);
    }

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

  helper_argv[0] = PACKAGE_PREFIX "/lib/polkit-1/polkit-agent-helper-1";
  helper_argv[1] = passwd->pw_name;
  helper_argv[2] = NULL;

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
                                 &stdin_fd,
                                 &session->child_stdout,
                                 NULL,
                                 &error))
    {
      g_warning ("Cannot spawn helper: %s\n", error->message);
      g_error_free (error);
      goto error;
    }

  if (G_UNLIKELY (_show_debug ()))
    g_print ("PolkitAgentSession: spawned helper with pid %d\n", (gint) session->child_pid);

  session->child_stdin = (GOutputStream*)g_unix_output_stream_new (stdin_fd, TRUE);

  /* Write the cookie on stdin so it can't be seen by other processes */
  (void) g_output_stream_write_all (session->child_stdin, session->cookie, strlen (session->cookie),
                                    NULL, NULL, NULL);
  (void) g_output_stream_write_all (session->child_stdin, "\n", 1, NULL, NULL, NULL);

  session->child_stdout_channel = g_io_channel_unix_new (session->child_stdout);
  session->child_stdout_watch_source = g_io_create_watch (session->child_stdout_channel,
                                                          G_IO_IN | G_IO_ERR | G_IO_HUP);
  g_source_set_callback (session->child_stdout_watch_source, (GSourceFunc) io_watch_have_data, session, NULL);
  g_source_attach (session->child_stdout_watch_source, g_main_context_get_thread_default ());


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
  g_return_if_fail (POLKIT_AGENT_IS_SESSION (session));

  if (G_UNLIKELY (_show_debug ()))
    g_print ("PolkitAgentSession: canceling authentication\n");

  complete_session (session, FALSE);
}

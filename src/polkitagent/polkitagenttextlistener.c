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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

#include <termios.h>
#include <unistd.h>

#include <polkit/polkitprivate.h>

#include "polkitagentlistener.h"
#include "polkitagenttextlistener.h"
#include "polkitagentsession.h"

/**
 * SECTION:polkitagenttextlistener
 * @title: PolkitAgentTextListener
 * @short_description: Text-based Authentication Agent
 * @stability: Unstable
 *
 * #PolkitAgentTextListener is an #PolkitAgentListener implementation
 * that interacts with the user using a textual interface.
 */

/**
 * PolkitAgentTextListener:
 *
 * The #PolkitAgentTextListener struct should not be accessed directly.
 */
struct _PolkitAgentTextListener
{
  PolkitAgentListener parent_instance;

  GSimpleAsyncResult *simple;
  PolkitAgentSession *active_session;
  gulong cancel_id;
  GCancellable *cancellable;

  FILE *tty;

  gboolean use_color;
  gboolean use_alternate_buffer;
  guint delay;
};

enum {
  PROP_ZERO,
  PROP_USE_COLOR,
  PROP_USE_ALTERNATE_BUFFER,
  PROP_DELAY
};

typedef struct
{
  PolkitAgentListenerClass parent_class;
} PolkitAgentTextListenerClass;

static void polkit_agent_text_listener_initiate_authentication (PolkitAgentListener  *_listener,
                                                                const gchar          *action_id,
                                                                const gchar          *message,
                                                                const gchar          *icon_name,
                                                                PolkitDetails        *details,
                                                                const gchar          *cookie,
                                                                GList                *identities,
                                                                GCancellable         *cancellable,
                                                                GAsyncReadyCallback   callback,
                                                                gpointer              user_data);

static gboolean polkit_agent_text_listener_initiate_authentication_finish (PolkitAgentListener  *_listener,
                                                                           GAsyncResult         *res,
                                                                           GError              **error);

static void initable_iface_init (GInitableIface *initable_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitAgentTextListener, polkit_agent_text_listener, POLKIT_AGENT_TYPE_LISTENER,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init));

static void
polkit_agent_text_listener_init (PolkitAgentTextListener *listener)
{
  listener->use_color = TRUE;
  listener->use_alternate_buffer = FALSE;
  listener->delay = 1;
}

static void
polkit_agent_text_listener_finalize (GObject *object)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (object);

  if (listener->tty != NULL)
    fclose (listener->tty);

  if (listener->active_session != NULL)
    g_object_unref (listener->active_session);

  if (G_OBJECT_CLASS (polkit_agent_text_listener_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_agent_text_listener_parent_class)->finalize (object);
}

static void
polkit_agent_text_listener_set_property (GObject      *object,
                                         guint         prop_id,
                                         const GValue *value,
                                         GParamSpec   *pspec)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (object);

  switch (prop_id)
    {
    case PROP_USE_COLOR:
      listener->use_color = g_value_get_boolean (value);
      break;
    case PROP_USE_ALTERNATE_BUFFER:
      listener->use_alternate_buffer = g_value_get_boolean (value);
      break;
    case PROP_DELAY:
      listener->delay = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_agent_text_listener_get_property (GObject    *object,
                                         guint       prop_id,
                                         GValue     *value,
                                         GParamSpec *pspec)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (object);

  switch (prop_id)
    {
    case PROP_USE_COLOR:
      g_value_set_boolean (value, listener->use_color);
      break;
    case PROP_USE_ALTERNATE_BUFFER:
      g_value_set_boolean (value, listener->use_alternate_buffer);
      break;
    case PROP_DELAY:
      g_value_set_uint (value, listener->delay);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_agent_text_listener_class_init (PolkitAgentTextListenerClass *klass)
{
  GObjectClass *gobject_class;
  PolkitAgentListenerClass *listener_class;

  gobject_class = G_OBJECT_CLASS (klass);
  gobject_class->finalize = polkit_agent_text_listener_finalize;
  gobject_class->get_property = polkit_agent_text_listener_get_property;
  gobject_class->set_property = polkit_agent_text_listener_set_property;

  listener_class = POLKIT_AGENT_LISTENER_CLASS (klass);
  listener_class->initiate_authentication        = polkit_agent_text_listener_initiate_authentication;
  listener_class->initiate_authentication_finish = polkit_agent_text_listener_initiate_authentication_finish;

  g_object_class_install_property (gobject_class,
                                   PROP_USE_COLOR,
                                   g_param_spec_boolean ("use-color", "", "",
                                                         TRUE,
                                                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class,
                                   PROP_USE_ALTERNATE_BUFFER,
                                   g_param_spec_boolean ("use-alternate-buffer", "", "",
                                                         FALSE,
                                                         G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (gobject_class,
                                   PROP_DELAY,
                                   g_param_spec_uint ("delay", "", "",
                                                      0, G_MAXUINT, 1,
                                                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

  g_signal_new("tty_attrs_changed",
               G_TYPE_FROM_CLASS(gobject_class),
               G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
               0, NULL, NULL, NULL,
               G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}

/**
 * polkit_agent_text_listener_new:
 * @cancellable: A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Creates a new #PolkitAgentTextListener for authenticating the user
 * via an textual interface on the controlling terminal
 * (e.g. <filename>/dev/tty</filename>). This can fail if e.g. the
 * current process has no controlling terminal.
 *
 * Returns: A #PolkitAgentTextListener or %NULL if @error is set. Free with g_object_unref() when done with it.
 */
PolkitAgentListener *
polkit_agent_text_listener_new (GCancellable  *cancellable,
                                GError       **error)
{
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);
  return POLKIT_AGENT_LISTENER (g_initable_new (POLKIT_AGENT_TYPE_TEXT_LISTENER,
                                                cancellable,
                                                error,
                                                NULL));
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
initable_init (GInitable     *initable,
               GCancellable  *cancellable,
               GError       **error)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (initable);
  gboolean ret;
  const gchar *tty_name;

  ret = FALSE;

  tty_name = ctermid (NULL);
  if (tty_name == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Cannot determine pathname for current controlling terminal for the process: %s",
                   strerror (errno));
      goto out;
    }

  listener->tty = fopen (tty_name, "r+");
  if (listener->tty == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error opening current controlling terminal for the process (`%s'): %s",
                   tty_name,
                   strerror (errno));
      goto out;
    }

  ret = TRUE;

 out:
  return ret;
}

static void
initable_iface_init (GInitableIface *initable_iface)
{
  initable_iface->init = initable_init;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
on_completed (PolkitAgentSession *session,
              gboolean            gained_authorization,
              gpointer            user_data)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (user_data);

  if (listener->use_color)
    fprintf (listener->tty, "\x1B[1;31m");
  if (gained_authorization)
    fprintf (listener->tty, "==== AUTHENTICATION COMPLETE ====\n");
  else
    fprintf (listener->tty, "==== AUTHENTICATION FAILED ====\n");
  if (listener->use_color)
    fprintf (listener->tty, "\x1B[0m");
  if (listener->use_alternate_buffer)
    {
      sleep (listener->delay);
      fprintf (listener->tty, "\x1B[?1049l");
    }
  fflush (listener->tty);

  g_simple_async_result_complete_in_idle (listener->simple);

  g_object_unref (listener->simple);
  g_object_unref (listener->active_session);
  g_cancellable_disconnect (listener->cancellable, listener->cancel_id);
  g_object_unref (listener->cancellable);

  listener->simple = NULL;
  listener->active_session = NULL;
  listener->cancel_id = 0;
}

static void
on_request (PolkitAgentSession *session,
            const gchar        *request,
            gboolean            echo_on,
            gpointer            user_data)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (user_data);
  struct termios ts, ots;
  GString *str;

  fprintf (listener->tty, "%s", request);
  fflush (listener->tty);

  setbuf (listener->tty, NULL);

  /* TODO: We really ought to block SIGINT and STGSTP (and probably
   *       other signals too) so we can restore the terminal (since we
   *       turn off echoing). See e.g. Advanced Programming in the
   *       UNIX Environment 2nd edition (Steves and Rago) section
   *       18.10, pg 660 where this is suggested. See also various
   *       getpass(3) implementations
   *
   *       However, since we are a library routine the user could have
   *       multiple threads - in fact, typical usage of
   *       PolkitAgentTextListener is to run it in a thread. And
   *       unfortunately threads and POSIX signals is a royal PITA.
   *
   *       Maybe we could fork(2) and ask for the password in the
   *       child and send it back to the parent over a pipe? (we are
   *       guaranteed that there is only one thread in the child
   *       process).
   *
   *       (Side benefit of doing this in a child process is that we
   *       could avoid blocking the thread where the
   *       PolkitAgentTextListener object is being serviced from. But
   *       since this class is normally used in a dedicated thread
   *       it doesn't really matter *anyway*.)
   *
   *       Anyway, On modern Linux not doing this doesn't seem to be a
   *       problem - looks like modern shells restore echoing anyway
   *       on the first input. So maybe it's not even worth solving
   *       the problem.
   */

  g_signal_emit_by_name(listener, "tty_attrs_changed", TRUE);
  tcgetattr (fileno (listener->tty), &ts);
  ots = ts;
  ts.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr (fileno (listener->tty), TCSAFLUSH, &ts);

  str = g_string_new (NULL);
  while (TRUE)
    {
      gint c;
      c = getc (listener->tty);
      if (c == '\n')
        {
          /* ok, done */
          break;
        }
      else if (c == EOF)
        {
          tcsetattr (fileno (listener->tty), TCSAFLUSH, &ots);
          g_error ("Got unexpected EOF while reading from controlling terminal.");
          abort ();
          break;
        }
      else
        {
          g_string_append_c (str, c);
        }
    }
  tcsetattr (fileno (listener->tty), TCSAFLUSH, &ots);
  g_signal_emit_by_name(listener, "tty_attrs_changed", FALSE);
  putc ('\n', listener->tty);

  polkit_agent_session_response (session, str->str);
  memset (str->str, '\0', str->len);
  g_string_free (str, TRUE);
}

static void
on_show_error (PolkitAgentSession *session,
               const gchar        *text,
               gpointer            user_data)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (user_data);
  fprintf (listener->tty, "Error: %s\n", text);
  fflush (listener->tty);
}

static void
on_show_info (PolkitAgentSession *session,
              const gchar        *text,
              gpointer            user_data)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (user_data);
  fprintf (listener->tty, "Info: %s\n", text);
  fflush (listener->tty);
}

static void
on_cancelled (GCancellable *cancellable,
              gpointer      user_data)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (user_data);
  fprintf (listener->tty, "Cancelled\n");
  fflush (listener->tty);
  polkit_agent_session_cancel (listener->active_session);
}

static gchar *
identity_to_human_readable_string (PolkitIdentity *identity)
{
  gchar *ret;

  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), NULL);

  ret = NULL;
  if (POLKIT_IS_UNIX_USER (identity))
    {
      struct passwd pw;
      struct passwd *ppw;
      char buf[2048];
      int res;

      res = getpwuid_r (polkit_unix_user_get_uid (POLKIT_UNIX_USER (identity)),
                        &pw,
                        buf,
                        sizeof buf,
                        &ppw);
      if (res != 0)
        {
          g_warning ("Error calling getpwuid_r: %s", strerror (res));
        }
      else
        {
          if (ppw->pw_gecos == NULL || strlen (ppw->pw_gecos) == 0 || strcmp (ppw->pw_gecos, ppw->pw_name) == 0)
            {
              ret = g_strdup_printf ("%s", ppw->pw_name);
            }
          else
            {
              ret = g_strdup_printf ("%s (%s)", ppw->pw_gecos, ppw->pw_name);
            }
        }
    }
  if (ret == NULL)
    ret = polkit_identity_to_string (identity);
  return ret;
}

static PolkitIdentity *
choose_identity (PolkitAgentTextListener *listener,
                 GList                   *identities)
{
  GList *l;
  guint n;
  guint num_identities;
  GString *str;
  PolkitIdentity *ret;
  guint num;
  gchar *endp;

  ret = NULL;

  fprintf (listener->tty, "Multiple identities can be used for authentication:\n");
  for (l = identities, n = 0; l != NULL; l = l->next, n++)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      gchar *s;
      s = identity_to_human_readable_string (identity);
      fprintf (listener->tty, " %d.  %s\n", n + 1, s);
      g_free (s);
    }
  num_identities = n;
  fprintf (listener->tty, "Choose identity to authenticate as (1-%d): ", num_identities);
  fflush (listener->tty);

  str = g_string_new (NULL);
  while (TRUE)
    {
      gint c;
      c = getc (listener->tty);
      if (c == '\n')
        {
          /* ok, done */
          break;
        }
      else if (c == EOF)
        {
          g_error ("Got unexpected EOF while reading from controlling terminal.");
          abort ();
          break;
        }
      else
        {
          g_string_append_c (str, c);
        }
    }

  num = strtol (str->str, &endp, 10);
  if (str->len == 0 || *endp != '\0' || (num < 1 || num > num_identities))
    {
      fprintf (listener->tty, "Invalid response `%s'.\n", str->str);
      goto out;
    }

  ret = g_list_nth_data (identities, num-1);

 out:
  g_string_free (str, TRUE);
  return ret;
}


static void
polkit_agent_text_listener_initiate_authentication (PolkitAgentListener  *_listener,
                                                    const gchar          *action_id,
                                                    const gchar          *message,
                                                    const gchar          *icon_name,
                                                    PolkitDetails        *details,
                                                    const gchar          *cookie,
                                                    GList                *identities,
                                                    GCancellable         *cancellable,
                                                    GAsyncReadyCallback   callback,
                                                    gpointer              user_data)
{
  PolkitAgentTextListener *listener = POLKIT_AGENT_TEXT_LISTENER (_listener);
  GSimpleAsyncResult *simple;
  PolkitIdentity *identity;

  simple = g_simple_async_result_new (G_OBJECT (listener),
                                      callback,
                                      user_data,
                                      polkit_agent_text_listener_initiate_authentication);
  if (listener->active_session != NULL)
    {
      g_simple_async_result_set_error (simple,
                                       POLKIT_ERROR,
                                       POLKIT_ERROR_FAILED,
                                       "An authentication session is already underway.");
      g_simple_async_result_complete_in_idle (simple);
      g_object_unref (simple);
      goto out;
    }

  g_assert (g_list_length (identities) >= 1);

  if (listener->use_alternate_buffer)
    fprintf (listener->tty, "\x1B[?1049h");
  if (listener->use_color)
    fprintf (listener->tty, "\x1B[1;31m");
  fprintf (listener->tty,
           "==== AUTHENTICATING FOR %s ====\n",
           action_id);
  if (listener->use_color)
    fprintf (listener->tty, "\x1B[0m");
  fprintf (listener->tty,
           "%s\n",
           message);

  /* handle multiple identies by asking which one to use */
  if (g_list_length (identities) > 1)
    {
      identity = choose_identity (listener, identities);
      if (identity == NULL)
        {
          if (listener->use_color)
            fprintf (listener->tty, "\x1B[1;31m");
          fprintf (listener->tty, "==== AUTHENTICATION CANCELED ====\n");
          if (listener->use_color)
            fprintf (listener->tty, "\x1B[0m");
          fflush (listener->tty);
          g_simple_async_result_set_error (simple,
                                           POLKIT_ERROR,
                                           POLKIT_ERROR_FAILED,
                                           "Authentication was canceled.");
          g_simple_async_result_complete_in_idle (simple);
          g_object_unref (simple);
          goto out;
        }
    }
  else
    {
      gchar *s;
      identity = identities->data;
      s = identity_to_human_readable_string (identity);
      fprintf (listener->tty,
               "Authenticating as: %s\n",
               s);
      g_free (s);
    }

  listener->active_session = polkit_agent_session_new (identity, cookie);
  g_signal_connect (listener->active_session,
                    "completed",
                    G_CALLBACK (on_completed),
                    listener);
  g_signal_connect (listener->active_session,
                    "request",
                    G_CALLBACK (on_request),
                    listener);
  g_signal_connect (listener->active_session,
                    "show-info",
                    G_CALLBACK (on_show_info),
                    listener);
  g_signal_connect (listener->active_session,
                    "show-error",
                    G_CALLBACK (on_show_error),
                    listener);

  listener->simple = simple;
  listener->cancellable = g_object_ref (cancellable);
  listener->cancel_id = g_cancellable_connect (cancellable,
                                               G_CALLBACK (on_cancelled),
                                               listener,
                                               NULL);

  polkit_agent_session_initiate (listener->active_session);

 out:
  ;
}

static gboolean
polkit_agent_text_listener_initiate_authentication_finish (PolkitAgentListener  *_listener,
                                                           GAsyncResult         *res,
                                                           GError              **error)
{
  gboolean ret;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) ==
                  polkit_agent_text_listener_initiate_authentication);

  ret = FALSE;

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
    goto out;

  ret = TRUE;

 out:
  return ret;
}

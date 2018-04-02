/*
 * Copyright (C) 2011 Red Hat, Inc.
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
 * Author: Matthias Clasen
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "polkitunixsession.h"
#include "polkitsubject.h"
#include "polkiterror.h"
#include "polkitprivate.h"

#include <systemd/sd-login.h>

/**
 * SECTION:polkitunixsession
 * @title: PolkitUnixSession
 * @short_description: Unix sessions
 *
 * An object that represents an user session.
 *
 * The session id is an opaque string obtained from ConsoleKit.
 */

/**
 * PolkitUnixSession:
 *
 * The #PolkitUnixSession struct should not be accessed directly.
 */
struct _PolkitUnixSession
{
  GObject parent_instance;

  gchar *session_id;

  gint pid;
};

struct _PolkitUnixSessionClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_SESSION_ID,
  PROP_PID,
};

static void subject_iface_init        (PolkitSubjectIface *subject_iface);
static void initable_iface_init       (GInitableIface *initable_iface);
static void async_initable_iface_init (GAsyncInitableIface *async_initable_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixSession, polkit_unix_session, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, async_initable_iface_init)
                         );

static void
polkit_unix_session_init (PolkitUnixSession *session)
{
}

static void
polkit_unix_session_finalize (GObject *object)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (object);

  g_free (session->session_id);

  if (G_OBJECT_CLASS (polkit_unix_session_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_unix_session_parent_class)->finalize (object);
}

static void
polkit_unix_session_get_property (GObject    *object,
                                  guint       prop_id,
                                  GValue     *value,
                                  GParamSpec *pspec)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (object);

  switch (prop_id)
    {
    case PROP_SESSION_ID:
      g_value_set_string (value, session->session_id);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_session_set_property (GObject      *object,
                                  guint         prop_id,
                                  const GValue *value,
                                  GParamSpec   *pspec)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (object);

  switch (prop_id)
    {
    case PROP_SESSION_ID:
      polkit_unix_session_set_session_id (session, g_value_get_string (value));
      break;

    case PROP_PID:
      session->pid = g_value_get_int (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_session_class_init (PolkitUnixSessionClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize     = polkit_unix_session_finalize;
  gobject_class->get_property = polkit_unix_session_get_property;
  gobject_class->set_property = polkit_unix_session_set_property;

  /**
   * PolkitUnixSession:session-id:
   *
   * The UNIX session id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_SESSION_ID,
                                   g_param_spec_string ("session-id",
                                                        "Session ID",
                                                        "The UNIX session ID",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));


  /**
   * PolkitUnixSession:pid:
   *
   * The UNIX process id to look up the session.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_PID,
                                   g_param_spec_int ("pid",
                                                     "Process ID",
                                                     "Process ID to use for looking up the session",
                                                     0,
                                                     G_MAXINT,
                                                     0,
                                                     G_PARAM_CONSTRUCT_ONLY |
                                                     G_PARAM_WRITABLE |
                                                     G_PARAM_STATIC_NAME |
                                                     G_PARAM_STATIC_BLURB |
                                                     G_PARAM_STATIC_NICK));

}

/**
 * polkit_unix_session_get_session_id:
 * @session: A #PolkitUnixSession.
 *
 * Gets the session id for @session.
 *
 * Returns: The session id for @session. Do not free this string, it
 * is owned by @session.
 **/
const gchar *
polkit_unix_session_get_session_id (PolkitUnixSession *session)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_SESSION (session), NULL);
  return session->session_id;
}

/**
 * polkit_unix_session_set_session_id:
 * @session: A #PolkitUnixSession.
 * @session_id: The session id.
 *
 * Sets the session id for @session to @session_id.
 **/
void
polkit_unix_session_set_session_id (PolkitUnixSession *session,
                                    const gchar       *session_id)
{
  g_return_if_fail (POLKIT_IS_UNIX_SESSION (session));
  /*g_return_if_fail (session_id != NULL);*/
  g_free (session->session_id);
  session->session_id = g_strdup (session_id);
}

/**
 * polkit_unix_session_new:
 * @session_id: The session id.
 *
 * Creates a new #PolkitUnixSession for @session_id.
 *
 * Returns: (transfer full): A #PolkitUnixSession. Free with g_object_unref().
 **/
PolkitSubject *
polkit_unix_session_new (const gchar *session_id)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_SESSION,
                                       "session-id", session_id,
                                       NULL));
}

/**
 * polkit_unix_session_new_for_process:
 * @pid: The process id of the process to get the session for.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously creates a new #PolkitUnixSession object for the
 * process with process id @pid.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_unix_session_new_for_process_finish() to get the result of
 * the operation.
 *
 * This method constructs the object asynchronously, for the synchronous and blocking version
 * use polkit_unix_session_new_for_process_sync().
 **/
void
polkit_unix_session_new_for_process (gint                pid,
                                     GCancellable       *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer            user_data)
{
  g_async_initable_new_async (POLKIT_TYPE_UNIX_SESSION,
                              G_PRIORITY_DEFAULT,
                              cancellable,
                              callback,
                              user_data,
                              "pid", pid,
                              NULL);
}

/**
 * polkit_unix_session_new_for_process_finish:
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to polkit_unix_session_new_for_process().
 * @error: (allow-none): Return location for error.
 *
 * Finishes constructing a #PolkitSubject for a process id.
 *
 * Returns: (transfer full) (allow-none): A #PolkitUnixSession for the @pid passed to
 *     polkit_unix_session_new_for_process() or %NULL if @error is
 *     set. Free with g_object_unref().
 **/
PolkitSubject *
polkit_unix_session_new_for_process_finish (GAsyncResult   *res,
                                            GError        **error)
{
  GObject *object;
  GObject *source_object;

  source_object = g_async_result_get_source_object (res);
  g_assert (source_object != NULL);

  object = g_async_initable_new_finish (G_ASYNC_INITABLE (source_object),
                                        res,
                                        error);
  g_object_unref (source_object);

  if (object != NULL)
    return POLKIT_SUBJECT (object);
  else
    return NULL;
}


/**
 * polkit_unix_session_new_for_process_sync:
 * @pid: The process id of the process to get the session for.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error.
 *
 * Creates a new #PolkitUnixSession for the process with process id @pid.
 *
 * This is a synchronous call - the calling thread is blocked until a
 * reply is received. For the asynchronous version, see
 * polkit_unix_session_new_for_process().
 *
 * Returns: (allow-none) (transfer full): A #PolkitUnixSession for
 * @pid or %NULL if @error is set. Free with g_object_unref().
 **/
PolkitSubject *
polkit_unix_session_new_for_process_sync (gint           pid,
                                          GCancellable  *cancellable,
                                          GError       **error)
{
  return POLKIT_SUBJECT (g_initable_new (POLKIT_TYPE_UNIX_SESSION,
                                         cancellable,
                                         error,
                                         "pid", pid,
                                         NULL));
}

static guint
polkit_unix_session_hash (PolkitSubject *subject)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (subject);

  return g_str_hash (session->session_id);
}

static gboolean
polkit_unix_session_equal (PolkitSubject *a,
                           PolkitSubject *b)
{
  PolkitUnixSession *session_a;
  PolkitUnixSession *session_b;

  session_a = POLKIT_UNIX_SESSION (a);
  session_b = POLKIT_UNIX_SESSION (b);

  return g_strcmp0 (session_a->session_id, session_b->session_id) == 0;
}

static gchar *
polkit_unix_session_to_string (PolkitSubject *subject)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (subject);

  return g_strdup_printf ("unix-session:%s", session->session_id);
}

static gboolean
polkit_unix_session_exists_sync (PolkitSubject   *subject,
                                 GCancellable    *cancellable,
                                 GError         **error)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (subject);
  gboolean ret = FALSE;
  uid_t uid;

  if (sd_session_get_uid (session->session_id, &uid) == 0)
    ret = TRUE;

  return ret;
}

static void
exists_in_thread_func (GSimpleAsyncResult *res,
                       GObject            *object,
                       GCancellable       *cancellable)
{
  GError *error;
  error = NULL;
  if (!polkit_unix_session_exists_sync (POLKIT_SUBJECT (object),
                                        cancellable,
                                        &error))
    {
      g_simple_async_result_set_from_error (res, error);
      g_error_free (error);
    }
}

static void
polkit_unix_session_exists (PolkitSubject       *subject,
                            GCancellable        *cancellable,
                            GAsyncReadyCallback  callback,
                            gpointer             user_data)
{
  GSimpleAsyncResult *simple;

  g_return_if_fail (POLKIT_IS_UNIX_SESSION (subject));

  simple = g_simple_async_result_new (G_OBJECT (subject),
                                      callback,
                                      user_data,
                                      polkit_unix_session_exists);
  g_simple_async_result_run_in_thread (simple,
                                       exists_in_thread_func,
                                       G_PRIORITY_DEFAULT,
                                       cancellable);
  g_object_unref (simple);
}

static gboolean
polkit_unix_session_exists_finish (PolkitSubject  *subject,
                                      GAsyncResult   *res,
                                      GError        **error)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);
  gboolean ret;

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_unix_session_exists);

  ret = FALSE;

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

  ret = g_simple_async_result_get_op_res_gboolean (simple);

 out:
  return ret;
}

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->hash          = polkit_unix_session_hash;
  subject_iface->equal         = polkit_unix_session_equal;
  subject_iface->to_string     = polkit_unix_session_to_string;
  subject_iface->exists        = polkit_unix_session_exists;
  subject_iface->exists_finish = polkit_unix_session_exists_finish;
  subject_iface->exists_sync   = polkit_unix_session_exists_sync;
}

static gboolean
polkit_unix_session_initable_init (GInitable     *initable,
                                   GCancellable  *cancellable,
                                   GError       **error)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (initable);
  gboolean ret = FALSE;
  char *s;
  uid_t uid;

  if (session->session_id != NULL)
    {
      /* already set, nothing to do */
      ret = TRUE;
      goto out;
    }

  if (sd_pid_get_session (session->pid, &s) == 0)
    {
      session->session_id = g_strdup (s);
      free (s);
      ret = TRUE;
      goto out;
    }

  /* Now do process -> uid -> graphical session (systemd version 213)*/
  if (sd_pid_get_owner_uid (session->pid, &uid) < 0)
    goto error;

  if (sd_uid_get_display (uid, &s) >= 0)
    {
      session->session_id =  g_strdup (s);
      free (s);
      ret = TRUE;
      goto out;
    }

error:
  g_set_error (error,
               POLKIT_ERROR,
               POLKIT_ERROR_FAILED,
               "No session for pid %d",
               (gint) session->pid);

out:
  return ret;
}

static void
initable_iface_init (GInitableIface *initable_iface)
{
  initable_iface->init = polkit_unix_session_initable_init;
}

static void
async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
  /* use default implementation to run GInitable code in a thread */
}

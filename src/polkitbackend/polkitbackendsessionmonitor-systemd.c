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

#include "config.h"
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <glib/gstdio.h>
#include <systemd/sd-login.h>
#include <stdlib.h>

#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>
#include "polkitbackendsessionmonitor.h"

/* <internal>
 * SECTION:polkitbackendsessionmonitor
 * @title: PolkitBackendSessionMonitor
 * @short_description: Monitor sessions
 *
 * The #PolkitBackendSessionMonitor class is a utility class to track and monitor sessions.
 */

typedef struct
{
  GSource source;
  GPollFD pollfd;
  sd_login_monitor *monitor;
} SdSource;

static gboolean
sd_source_prepare (GSource *source,
                   gint    *timeout)
{
  *timeout = -1;
  return FALSE;
}

static gboolean
sd_source_check (GSource *source)
{
  SdSource *sd_source = (SdSource *)source;

  return sd_source->pollfd.revents != 0;
}

static gboolean
sd_source_dispatch (GSource     *source,
                    GSourceFunc  callback,
                    gpointer     user_data)

{
  SdSource *sd_source = (SdSource *)source;
  gboolean ret;

  g_warn_if_fail (callback != NULL);

  ret = (*callback) (user_data);

  sd_login_monitor_flush (sd_source->monitor);

  return ret;
}

static void
sd_source_finalize (GSource *source)
{
  SdSource *sd_source = (SdSource*)source;

  sd_login_monitor_unref (sd_source->monitor);
}

static GSourceFuncs sd_source_funcs = {
  sd_source_prepare,
  sd_source_check,
  sd_source_dispatch,
  sd_source_finalize
};

static GSource *
sd_source_new (void)
{
  GSource *source;
  SdSource *sd_source;
  int ret;

  source = g_source_new (&sd_source_funcs, sizeof (SdSource));
  sd_source = (SdSource *)source;

  if ((ret = sd_login_monitor_new (NULL, &sd_source->monitor)) < 0)
    {
      g_printerr ("Error getting login monitor: %d", ret);
    }
  else
    {
      sd_source->pollfd.fd = sd_login_monitor_get_fd (sd_source->monitor);
      sd_source->pollfd.events = G_IO_IN;
      g_source_add_poll (source, &sd_source->pollfd);
    }

  return source;
}

struct _PolkitBackendSessionMonitor
{
  GObject parent_instance;

  GDBusConnection *system_bus;

  GSource *sd_source;
};

struct _PolkitBackendSessionMonitorClass
{
  GObjectClass parent_class;

  void (*changed) (PolkitBackendSessionMonitor *monitor);
};


enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (PolkitBackendSessionMonitor, polkit_backend_session_monitor, G_TYPE_OBJECT);

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
sessions_changed (gpointer user_data)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (user_data);

  g_signal_emit (monitor, signals[CHANGED_SIGNAL], 0);

  return TRUE;
}


static void
polkit_backend_session_monitor_init (PolkitBackendSessionMonitor *monitor)
{
  GError *error;

  error = NULL;
  monitor->system_bus = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  if (monitor->system_bus == NULL)
    {
      g_printerr ("Error getting system bus: %s", error->message);
      g_error_free (error);
    }

  monitor->sd_source = sd_source_new ();
  g_source_set_callback (monitor->sd_source, sessions_changed, monitor, NULL);
  g_source_attach (monitor->sd_source, NULL);
}

static void
polkit_backend_session_monitor_finalize (GObject *object)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (object);

  if (monitor->system_bus != NULL)
    g_object_unref (monitor->system_bus);

  if (monitor->sd_source != NULL)
    {
      g_source_destroy (monitor->sd_source);
      g_source_unref (monitor->sd_source);
    }

  if (G_OBJECT_CLASS (polkit_backend_session_monitor_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_backend_session_monitor_parent_class)->finalize (object);
}

static void
polkit_backend_session_monitor_class_init (PolkitBackendSessionMonitorClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_backend_session_monitor_finalize;

  /**
   * PolkitBackendSessionMonitor::changed:
   * @monitor: A #PolkitBackendSessionMonitor
   *
   * Emitted when something changes.
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_BACKEND_TYPE_SESSION_MONITOR,
                                          G_SIGNAL_RUN_LAST,
                                          G_STRUCT_OFFSET (PolkitBackendSessionMonitorClass, changed),
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

PolkitBackendSessionMonitor *
polkit_backend_session_monitor_new (void)
{
  PolkitBackendSessionMonitor *monitor;

  monitor = POLKIT_BACKEND_SESSION_MONITOR (g_object_new (POLKIT_BACKEND_TYPE_SESSION_MONITOR, NULL));

  return monitor;
}

/* ---------------------------------------------------------------------------------------------------- */

GList *
polkit_backend_session_monitor_get_sessions (PolkitBackendSessionMonitor *monitor)
{
  /* TODO */
  return NULL;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_backend_session_monitor_get_user:
 * @monitor: A #PolkitBackendSessionMonitor.
 * @subject: A #PolkitSubject.
 * @result_matches: If not %NULL, set to indicate whether the return value matches current (RACY) state.
 * @error: Return location for error.
 *
 * Gets the user corresponding to @subject or %NULL if no user exists.
 *
 * NOTE: For a #PolkitUnixProcess, the UID is read from @subject (which may
 * come from e.g. a D-Bus client), so it may not correspond to the actual UID
 * of the referenced process (at any point in time).  This is indicated by
 * setting @result_matches to %FALSE; the caller may reject such subjects or
 * require additional privileges. @result_matches == %TRUE only indicates that
 * the UID matched the underlying process at ONE point in time, it may not match
 * later.
 *
 * Returns: %NULL if @error is set otherwise a #PolkitUnixUser that should be freed with g_object_unref().
 */
PolkitIdentity *
polkit_backend_session_monitor_get_user_for_subject (PolkitBackendSessionMonitor  *monitor,
                                                     PolkitSubject                *subject,
                                                     gboolean                     *result_matches,
                                                     GError                      **error)
{
  PolkitIdentity *ret;
  gboolean matches;

  ret = NULL;
  matches = FALSE;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      gint subject_uid, current_uid;
      GError *local_error;

      subject_uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (subject));
      if (subject_uid == -1)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Unix process subject does not have uid set");
          goto out;
        }
      local_error = NULL;
      current_uid = polkit_unix_process_get_racy_uid__ (POLKIT_UNIX_PROCESS (subject), &local_error);
      if (local_error != NULL)
	{
	  g_propagate_error (error, local_error);
	  goto out;
	}
      ret = polkit_unix_user_new (subject_uid);
      matches = (subject_uid == current_uid);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      ret = (PolkitIdentity*)polkit_system_bus_name_get_user_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, error);
      matches = TRUE;
    }
  else if (POLKIT_IS_UNIX_SESSION (subject))
    {
      uid_t uid;

      if (sd_session_get_uid (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (subject)), &uid) < 0)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Error getting uid for session");
          goto out;
        }

      ret = polkit_unix_user_new (uid);
      matches = TRUE;
    }

 out:
  if (result_matches != NULL)
    {
      *result_matches = matches;
    }
  return ret;
}

/**
 * polkit_backend_session_monitor_get_session_for_subject:
 * @monitor: A #PolkitBackendSessionMonitor.
 * @subject: A #PolkitSubject.
 * @error: Return location for error.
 *
 * Gets the session corresponding to @subject or %NULL if no session exists.
 *
 * Returns: %NULL if @error is set otherwise a #PolkitUnixSession that should be freed with g_object_unref().
 */
PolkitSubject *
polkit_backend_session_monitor_get_session_for_subject (PolkitBackendSessionMonitor *monitor,
                                                        PolkitSubject               *subject,
                                                        GError                     **error)
{
  PolkitUnixProcess *tmp_process = NULL;
  PolkitUnixProcess *process = NULL;
  PolkitSubject *session = NULL;
  char *session_id = NULL;
  pid_t pid;
#if HAVE_SD_UID_GET_DISPLAY
  uid_t uid;
#endif

  if (POLKIT_IS_UNIX_PROCESS (subject))
    process = POLKIT_UNIX_PROCESS (subject); /* We already have a process */
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      /* Convert bus name to process */
      tmp_process = (PolkitUnixProcess*)polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, error);
      if (!tmp_process)
	goto out;
      process = tmp_process;
    }
  else
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Cannot get session for subject of type %s",
                   g_type_name (G_TYPE_FROM_INSTANCE (subject)));
    }

  /* Now do process -> pid -> same session */
  g_assert (process != NULL);
  pid = polkit_unix_process_get_pid (process);

  if (sd_pid_get_session (pid, &session_id) >= 0)
    {
      session = polkit_unix_session_new (session_id);
      goto out;
    }

#if HAVE_SD_UID_GET_DISPLAY
  /* Now do process -> uid -> graphical session (systemd version 213)*/
  if (sd_pid_get_owner_uid (pid, &uid) < 0)
    goto out;

  if (sd_uid_get_display (uid, &session_id) >= 0)
    {
      session = polkit_unix_session_new (session_id);
      goto out;
    }
#endif

 out:
  free (session_id);
  if (tmp_process) g_object_unref (tmp_process);
  return session;
}

gboolean
polkit_backend_session_monitor_is_session_local (PolkitBackendSessionMonitor *monitor,
                                                 PolkitSubject               *session)
{
  char *seat;

  if (!sd_session_get_seat (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session)), &seat))
    {
      free (seat);
      return TRUE;
    }

  return FALSE;
}


gboolean
polkit_backend_session_monitor_is_session_active (PolkitBackendSessionMonitor *monitor,
                                                  PolkitSubject               *session)
{
  const char *session_id;
  char *state;
  uid_t uid;
  gboolean is_active = FALSE;

  session_id = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session));

  g_debug ("Checking whether session %s is active.", session_id);

  /* Check whether *any* of the user's current sessions are active. */
  if (sd_session_get_uid (session_id, &uid) < 0)
    goto fallback;

  g_debug ("Session %s has UID %u.", session_id, uid);

  if (sd_uid_get_state (uid, &state) < 0)
    goto fallback;

  g_debug ("UID %u has state %s.", uid, state);

  is_active = (g_strcmp0 (state, "active") == 0);
  free (state);

  return is_active;

fallback:
  /* Fall back to checking the session. This is not ideal, since the user
   * might have multiple sessions, and we cannot guarantee to have chosen
   * the active one.
   *
   * See: https://bugs.freedesktop.org/show_bug.cgi?id=76358. */
  return sd_session_is_active (session_id);
}


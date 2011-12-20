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
 * @error: Return location for error.
 *
 * Gets the user corresponding to @subject or %NULL if no user exists.
 *
 * Returns: %NULL if @error is set otherwise a #PolkitUnixUser that should be freed with g_object_unref().
 */
PolkitIdentity *
polkit_backend_session_monitor_get_user_for_subject (PolkitBackendSessionMonitor  *monitor,
                                                     PolkitSubject                *subject,
                                                     GError                      **error)
{
  PolkitIdentity *ret;
  guint32 uid;

  ret = NULL;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      uid = polkit_unix_process_get_uid (POLKIT_UNIX_PROCESS (subject));
      if ((gint) uid == -1)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Unix process subject does not have uid set");
          goto out;
        }
      ret = polkit_unix_user_new (uid);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      GVariant *result;

      result = g_dbus_connection_call_sync (monitor->system_bus,
                                            "org.freedesktop.DBus",
                                            "/org/freedesktop/DBus",
                                            "org.freedesktop.DBus",
                                            "GetConnectionUnixUser",
                                            g_variant_new ("(s)", polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject))),
                                            G_VARIANT_TYPE ("(u)"),
                                            G_DBUS_CALL_FLAGS_NONE,
                                            -1, /* timeout_msec */
                                            NULL, /* GCancellable */
                                            error);
      if (result == NULL)
        goto out;
      g_variant_get (result, "(u)", &uid);
      g_variant_unref (result);

      ret = polkit_unix_user_new (uid);
    }
  else if (POLKIT_IS_UNIX_SESSION (subject))
    {

      if (sd_session_get_uid (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (subject)), &uid) < 0)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Error getting uid for session");
          goto out;
        }

      ret = polkit_unix_user_new (uid);
    }

 out:
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
  PolkitSubject *session;

  session = NULL;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      gchar *session_id;
      pid_t pid;

      pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject));
      if (sd_pid_get_session (pid, &session_id) < 0)
        goto out;

      session = polkit_unix_session_new (session_id);
      free (session_id);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      guint32 pid;
      gchar *session_id;
      GVariant *result;

      result = g_dbus_connection_call_sync (monitor->system_bus,
                                            "org.freedesktop.DBus",
                                            "/org/freedesktop/DBus",
                                            "org.freedesktop.DBus",
                                            "GetConnectionUnixProcessID",
                                            g_variant_new ("(s)", polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject))),
                                            G_VARIANT_TYPE ("(u)"),
                                            G_DBUS_CALL_FLAGS_NONE,
                                            -1, /* timeout_msec */
                                            NULL, /* GCancellable */
                                            error);
      if (result == NULL)
        goto out;
      g_variant_get (result, "(u)", &pid);
      g_variant_unref (result);

      if (sd_pid_get_session (pid, &session_id) < 0)
        goto out;

      session = polkit_unix_session_new (session_id);
      free (session_id);
    }
  else
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_NOT_SUPPORTED,
                   "Cannot get user for subject of type %s",
                   g_type_name (G_TYPE_FROM_INSTANCE (subject)));
    }

 out:

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
  return sd_session_is_active (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session)));
}


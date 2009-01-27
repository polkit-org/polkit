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
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <polkit/polkit.h>
#include "polkitbackendsessionmonitor.h"
#include "ckbindings.h"

/**
 * SECTION:polkitbackendsessionmonitor
 * @title: PolkitBackendSessionMonitor
 * @short_description: Monitor sessions
 *
 * The #PolkitBackendSessionMonitor is a utility class to track and monitor sessions.
 */

struct _PolkitBackendSessionMonitor
{
  GObject parent_instance;

  EggDBusConnection *system_bus;

  EggDBusObjectProxy *ck_manager_object_proxy;

  CkManager *ck_manager;
  EggDBusHashMap *seat_object_path_to_object_proxy;
  EggDBusHashMap *session_object_path_to_object_proxy;
};

struct _PolkitBackendSessionMonitorClass
{
  GObjectClass parent_class;

};

static void seat_session_added (CkSeat      *seat,
                                const gchar *object_path,
                                gpointer     user_data);

static void seat_session_removed (CkSeat      *seat,
                                  const gchar *object_path,
                                  gpointer     user_data);

static void session_active_changed (CkSession   *session,
                                    gboolean     is_active,
                                    gpointer     user_data);

G_DEFINE_TYPE (PolkitBackendSessionMonitor, polkit_backend_session_monitor, G_TYPE_OBJECT);

/* ---------------------------------------------------------------------------------------------------- */

static void
add_seat (PolkitBackendSessionMonitor *monitor,
          const gchar                 *object_path)
{
  CkSeat *seat;
  EggDBusObjectProxy *object_proxy;

  object_proxy = egg_dbus_connection_get_object_proxy (monitor->system_bus,
                                                       "org.freedesktop.ConsoleKit",
                                                       object_path);

  egg_dbus_hash_map_insert (monitor->seat_object_path_to_object_proxy,
                            g_strdup (object_path),
                            object_proxy);

  seat = CK_QUERY_INTERFACE_SEAT (object_proxy);

  g_signal_connect (seat,
                    "session-added",
                    G_CALLBACK (seat_session_added),
                    monitor);

  g_signal_connect (seat,
                    "session-removed",
                    G_CALLBACK (seat_session_removed),
                    monitor);
}

static void
add_session (PolkitBackendSessionMonitor *monitor,
             const gchar                 *object_path)
{
  CkSession *session;
  EggDBusObjectProxy *object_proxy;

  object_proxy = egg_dbus_connection_get_object_proxy (monitor->system_bus,
                                                       "org.freedesktop.ConsoleKit",
                                                       object_path);

  egg_dbus_hash_map_insert (monitor->session_object_path_to_object_proxy,
                            g_strdup (object_path),
                            object_proxy);

  session = CK_QUERY_INTERFACE_SESSION (object_proxy);

  g_signal_connect (session,
                    "active-changed",
                    G_CALLBACK (session_active_changed),
                    monitor);
}

static void
remove_seat (PolkitBackendSessionMonitor *monitor,
             const gchar                 *object_path)
{
  egg_dbus_hash_map_remove (monitor->seat_object_path_to_object_proxy,
                            object_path);
}

static void
remove_session (PolkitBackendSessionMonitor *monitor,
                const gchar                 *object_path)
{
  egg_dbus_hash_map_remove (monitor->session_object_path_to_object_proxy,
                            object_path);
}

/* ---------------------------------------------------------------------------------------------------- */

/* D-Bus signal handlers */

static void
manager_seat_added (CkManager   *manager,
                    const gchar *object_path,
                    gpointer     user_data)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (user_data);

  //g_debug ("seat %s added", object_path);

  add_seat (monitor, object_path);
}

static void
manager_seat_removed (CkManager   *manager,
                      const gchar *object_path,
                      gpointer     user_data)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (user_data);

  //g_debug ("seat %s removed", object_path);

  remove_seat (monitor, object_path);
}

static void
seat_session_added (CkSeat      *seat,
                    const gchar *object_path,
                    gpointer     user_data)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (user_data);

  //g_debug ("session %s added", object_path);

  add_session (monitor, object_path);
}

static void
seat_session_removed (CkSeat      *seat,
                      const gchar *object_path,
                      gpointer     user_data)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (user_data);

  //g_debug ("session %s removed", object_path);

  remove_session (monitor, object_path);
}

static void
session_active_changed (CkSession   *session,
                        gboolean     is_active,
                        gpointer     user_data)
{
  EggDBusObjectProxy *object_proxy;

  object_proxy = egg_dbus_interface_proxy_get_object_proxy (EGG_DBUS_INTERFACE_PROXY (session));

  //g_debug ("session %s active changed to %d", egg_dbus_object_proxy_get_object_path (object_proxy), is_active);

  egg_dbus_object_proxy_invalidate_properties (object_proxy);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_session_monitor_init (PolkitBackendSessionMonitor *monitor)
{
  GError *error;
  gchar **seats_object_paths;
  gchar **sessions_object_paths;
  guint n;

  error = NULL;
  seats_object_paths = NULL;
  sessions_object_paths = NULL;

  monitor->seat_object_path_to_object_proxy = egg_dbus_hash_map_new (G_TYPE_STRING,
                                                                     g_free,
                                                                     EGG_DBUS_TYPE_OBJECT_PROXY,
                                                                     g_object_unref);

  monitor->session_object_path_to_object_proxy = egg_dbus_hash_map_new (G_TYPE_STRING,
                                                                        g_free,
                                                                        EGG_DBUS_TYPE_OBJECT_PROXY,
                                                                        g_object_unref);

  monitor->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  monitor->ck_manager_object_proxy = egg_dbus_connection_get_object_proxy (monitor->system_bus,
                                                                           "org.freedesktop.ConsoleKit",
                                                                           "/org/freedesktop/ConsoleKit/Manager");

  monitor->ck_manager = CK_QUERY_INTERFACE_MANAGER (monitor->ck_manager_object_proxy);

  g_signal_connect (monitor->ck_manager,
                    "seat-added",
                    G_CALLBACK (manager_seat_added),
                    monitor);

  g_signal_connect (monitor->ck_manager,
                    "seat-removed",
                    G_CALLBACK (manager_seat_removed),
                    monitor);

  /* TODO: it would be a lot nicer to do all of this async; once we have
   *       GFiber (bgo #565501) it will be a lot easier...
   */
  if (!ck_manager_get_seats_sync (monitor->ck_manager,
                                  EGG_DBUS_CALL_FLAGS_NONE,
                                  &seats_object_paths,
                                  NULL,
                                  &error))
    {
      g_warning ("Error getting seats: %s", error->message);
      g_error_free (error);
      goto out;
    }

  for (n = 0; seats_object_paths[n] != NULL; n++)
    add_seat (monitor, seats_object_paths[n]);

  if (!ck_manager_get_sessions_sync (monitor->ck_manager,
                                     EGG_DBUS_CALL_FLAGS_NONE,
                                     &sessions_object_paths,
                                     NULL,
                                     &error))
    {
      g_warning ("Error getting sessions: %s", error->message);
      g_error_free (error);
      goto out;
    }

  for (n = 0; sessions_object_paths[n] != NULL; n++)
    add_session (monitor, sessions_object_paths[n]);

 out:

  g_strfreev (seats_object_paths);
  g_strfreev (sessions_object_paths);
}

static void
polkit_backend_session_monitor_finalize (GObject *object)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (object);

  g_object_unref (monitor->seat_object_path_to_object_proxy);
  g_object_unref (monitor->session_object_path_to_object_proxy);
  g_object_unref (monitor->ck_manager_object_proxy);
  g_object_unref (monitor->system_bus);

  if (G_OBJECT_CLASS (polkit_backend_session_monitor_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_backend_session_monitor_parent_class)->finalize (object);
}

static void
polkit_backend_session_monitor_class_init (PolkitBackendSessionMonitorClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_backend_session_monitor_finalize;
}

PolkitBackendSessionMonitor *
polkit_backend_session_monitor_new (void)
{
  PolkitBackendSessionMonitor *monitor;

  monitor = POLKIT_BACKEND_SESSION_MONITOR (g_object_new (POLKIT_BACKEND_TYPE_SESSION_MONITOR, NULL));

  return monitor;
}

static gboolean
get_sessions_foreach_cb (EggDBusHashMap *map,
                         gpointer        key,
                         gpointer        value,
                         gpointer        user_data)
{
  GList **l;
  const gchar *session_object_path;
  PolkitSubject *session;

  l = user_data;
  session_object_path = key;

  session = polkit_unix_session_new (session_object_path);

  *l = g_list_prepend (*l, session);

  return FALSE;
}

/* ---------------------------------------------------------------------------------------------------- */

GList *
polkit_backend_session_monitor_get_sessions (PolkitBackendSessionMonitor *monitor)
{
  GList *l;

  l = NULL;

  egg_dbus_hash_map_foreach (monitor->session_object_path_to_object_proxy,
                             get_sessions_foreach_cb,
                             &l);

  l = g_list_reverse (l);

  return l;
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
  PolkitIdentity *user;
  uid_t uid;

  user = NULL;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      pid_t pid;

      pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject));
      uid = 500; /* TODO */

      user = polkit_unix_user_new (uid);
    }
  else if (POLKIT_IS_UNIX_SESSION (subject))
    {
      const gchar *session_id;
      EggDBusObjectProxy *session_object_proxy;
      CkSession *session;

      session_id = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (subject));

      session_object_proxy = egg_dbus_hash_map_lookup (monitor->session_object_path_to_object_proxy,
                                                       session_id);
      if (session_object_proxy == NULL)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "No ConsoleKit session with id %s",
                       session_id);
          goto out;
        }

      session = CK_QUERY_INTERFACE_SESSION (session_object_proxy);

      uid = (uid_t) ck_session_get_user (session);

      user = polkit_unix_user_new (uid);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      /* TODO: cache this stuff */
      if (!egg_dbus_bus_get_connection_unix_user_sync (egg_dbus_connection_get_bus (monitor->system_bus),
                                                       EGG_DBUS_CALL_FLAGS_NONE,
                                                       polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                                                       &uid,
                                                       NULL,
                                                       error))
        goto out;

      user = polkit_unix_user_new (uid);
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

  return user;
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

      if (!ck_manager_get_session_for_unix_process_sync (monitor->ck_manager,
                                                         EGG_DBUS_CALL_FLAGS_NONE,
                                                         polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject)),
                                                         &session_id,
                                                         NULL,
                                                         error))
        goto out;

      session = polkit_unix_session_new (session_id);

      g_free (session_id);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      pid_t pid;
      gchar *session_id;

      /* TODO: cache this stuff */
      if (!egg_dbus_bus_get_connection_unix_process_id_sync (egg_dbus_connection_get_bus (monitor->system_bus),
                                                             EGG_DBUS_CALL_FLAGS_NONE,
                                                             polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                                                             &pid,
                                                             NULL,
                                                             error))
        goto out;

      if (!ck_manager_get_session_for_unix_process_sync (monitor->ck_manager,
                                                         EGG_DBUS_CALL_FLAGS_NONE,
                                                         pid,
                                                         &session_id,
                                                         NULL,
                                                         error))
        goto out;

      session = polkit_unix_session_new (session_id);

      g_free (session_id);
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
polkit_backend_session_monitor_is_session_local  (PolkitBackendSessionMonitor *monitor,
                                                  PolkitSubject               *session)
{
  EggDBusObjectProxy *object_proxy;
  const gchar *session_id;
  CkSession *ck_session;
  gboolean ret;

  g_return_val_if_fail (POLKIT_IS_UNIX_SESSION (session), FALSE);

  ret = FALSE;

  session_id = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session));

  object_proxy = egg_dbus_hash_map_lookup (monitor->session_object_path_to_object_proxy, session_id);
  if (object_proxy == NULL)
    goto out;

  ck_session = CK_QUERY_INTERFACE_SESSION (object_proxy);

  ret = ck_session_get_is_local (ck_session);

 out:
  return ret;
}


gboolean
polkit_backend_session_monitor_is_session_active (PolkitBackendSessionMonitor *monitor,
                                                  PolkitSubject               *session)
{
  EggDBusObjectProxy *object_proxy;
  const gchar *session_id;
  CkSession *ck_session;
  gboolean ret;

  g_return_val_if_fail (POLKIT_IS_UNIX_SESSION (session), FALSE);

  ret = FALSE;

  session_id = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session));

  object_proxy = egg_dbus_hash_map_lookup (monitor->session_object_path_to_object_proxy, session_id);
  if (object_proxy == NULL)
    goto out;

  ck_session = CK_QUERY_INTERFACE_SESSION (object_proxy);

  ret = ck_session_get_active (ck_session);

 out:
  return ret;
}


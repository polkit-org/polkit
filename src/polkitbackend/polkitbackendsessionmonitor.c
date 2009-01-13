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

struct _PolkitBackendSessionMonitor
{
  GObject parent_instance;

  EggDBusObjectProxy *ck_manager_object_proxy;
  CkManager *ck_manager;
};

struct _PolkitBackendSessionMonitorClass
{
  GObjectClass parent_class;

};

G_DEFINE_TYPE (PolkitBackendSessionMonitor, polkit_backend_session_monitor, G_TYPE_OBJECT);

static void
polkit_backend_session_monitor_init (PolkitBackendSessionMonitor *monitor)
{
  EggDBusConnection *system_bus;

  system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  monitor->ck_manager_object_proxy = egg_dbus_connection_get_object_proxy (system_bus,
                                                                           "org.freedesktop.ConsoleKit",
                                                                           "/org/freedesktop/ConsoleKit/Manager");

  monitor->ck_manager = CK_QUERY_INTERFACE_MANAGER (monitor->ck_manager_object_proxy);

  g_object_unref (system_bus);
}

static void
polkit_backend_session_monitor_finalize (GObject *object)
{
  PolkitBackendSessionMonitor *monitor = POLKIT_BACKEND_SESSION_MONITOR (object);

  g_object_unref (monitor->ck_manager_object_proxy);

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


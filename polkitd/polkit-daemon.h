/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 David Zeuthen <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef __POLKIT_DAEMON_H__
#define __POLKIT_DAEMON_H__

#include <glib-object.h>
#include <polkit-dbus/polkit-dbus.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_DAEMON         (polkit_daemon_get_type ())
#define POLKIT_DAEMON(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_DAEMON, PolKitDaemon))
#define POLKIT_DAEMON_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_DAEMON, PolKitDaemonClass))
#define POLKIT_IS_DAEMON(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_DAEMON))
#define POLKIT_IS_DAEMON_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_DAEMON))
#define POLKIT_DAEMON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_DAEMON, PolKitDaemonClass))

typedef struct PolKitDaemonPrivate PolKitDaemonPrivate;

typedef struct
{
        GObject        parent;
        PolKitDaemonPrivate *priv;
} PolKitDaemon;

typedef struct
{
        GObjectClass   parent_class;
} PolKitDaemonClass;

typedef enum
{
        POLKIT_DAEMON_ERROR_GENERAL,
        POLKIT_DAEMON_ERROR_NOT_AUTHORIZED,
        POLKIT_DAEMON_NUM_ERRORS
} PolKitDaemonError;

#define POLKIT_DAEMON_ERROR polkit_daemon_error_quark ()

GType polkit_daemon_error_get_type (void);
#define POLKIT_DAEMON_TYPE_ERROR (polkit_daemon_error_get_type ())

GQuark        polkit_daemon_error_quark         (void);
GType         polkit_daemon_get_type            (void);
PolKitDaemon *polkit_daemon_new                 (gboolean no_exit);

/* exported methods */

gboolean polkit_daemon_is_process_authorized         (PolKitDaemon          *daemon,
                                                      const char            *action_id, 
                                                      guint32                pid,
                                                      gboolean               is_mechanism,
                                                      DBusGMethodInvocation *context);

gboolean polkit_daemon_is_system_bus_name_authorized (PolKitDaemon          *daemon,
                                                      const char            *action_id, 
                                                      const char            *system_bus_name,
                                                      gboolean               is_mechanism,
                                                      DBusGMethodInvocation *context);

G_END_DECLS

#endif /* __POLKIT_DAEMON_H__ */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*-
 *
 * Copyright (C) 2007 David Zeuthen <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
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
                                                      gboolean               revoke_if_one_shot,
                                                      DBusGMethodInvocation *context);

gboolean polkit_daemon_is_system_bus_name_authorized (PolKitDaemon          *daemon,
                                                      const char            *action_id, 
                                                      const char            *system_bus_name,
                                                      gboolean               revoke_if_one_shot,
                                                      DBusGMethodInvocation *context);

G_END_DECLS

#endif /* __POLKIT_DAEMON_H__ */

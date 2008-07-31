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

#ifndef __POLKIT_DAEMON_BACKEND_H__
#define __POLKIT_DAEMON_BACKEND_H__

#include <glib-object.h>
#include <polkit/polkit.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_DAEMON_BACKEND         (polkit_daemon_backend_get_type ())
#define POLKIT_DAEMON_BACKEND(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_DAEMON_BACKEND, PolKitDaemonBackend))
#define POLKIT_DAEMON_BACKEND_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_DAEMON_BACKEND, PolKitDaemonBackendClass))
#define POLKIT_IS_DAEMON_BACKEND(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_DAEMON_BACKEND))
#define POLKIT_IS_DAEMON_BACKEND_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_DAEMON_BACKEND))
#define POLKIT_DAEMON_BACKEND_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_DAEMON_BACKEND, PolKitDaemonBackendClass))

typedef struct PolKitDaemonBackendPrivate PolKitDaemonBackendPrivate;

typedef struct
{
        GObject        parent;
        PolKitDaemonBackendPrivate *priv;
} PolKitDaemonBackend;

typedef struct
{
        GObjectClass   parent_class;
} PolKitDaemonBackendClass;

typedef enum
{
        POLKIT_DAEMON_BACKEND_ERROR_GENERAL,
        POLKIT_DAEMON_BACKEND_NUM_ERRORS
} PolKitDaemonBackendError;

#define POLKIT_DAEMON_BACKEND_ERROR polkit_daemon_backend_error_quark ()

GType polkit_daemon_backend_error_get_type (void);
#define POLKIT_DAEMON_BACKEND_TYPE_ERROR (polkit_daemon_backend_error_get_type ())

GQuark               polkit_daemon_backend_error_quark         (void);
GType                polkit_daemon_backend_get_type            (void);
PolKitDaemonBackend *polkit_daemon_backend_new                 (gboolean no_exit);

/* exported methods */

gboolean polkit_daemon_backend_hello (PolKitDaemonBackend   *daemon,
                                      const char            *message,
                                      DBusGMethodInvocation *context);

G_END_DECLS

#endif /* __POLKIT_DAEMON_BACKEND_H__ */

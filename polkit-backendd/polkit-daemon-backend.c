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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>

#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "polkit-daemon-backend.h"

#include <polkit/polkit.h>
#include <polkit/polkit-private.h>

static gboolean no_exit = FALSE;

/*--------------------------------------------------------------------------------------------------------------*/
#include "polkit-daemon-backend-glue.h"

static gboolean
do_exit (gpointer user_data)
{
        g_debug ("Exiting due to inactivity");
        exit (1);
        return FALSE;
}

static void
reset_killtimer (void)
{
        static guint timer_id = 0;

        if (no_exit)
                return;

        if (timer_id > 0) {
                g_source_remove (timer_id);
        }
        g_debug ("Setting killtimer to 30 seconds...");
        timer_id = g_timeout_add (30 * 1000, do_exit, NULL);
}

struct PolKitDaemonBackendPrivate
{
        DBusGConnection *system_bus_connection;
        DBusGProxy      *system_bus_proxy;
        PolKitContext   *pk_context;
        PolKitTracker   *pk_tracker;
};

static void     polkit_daemon_backend_class_init  (PolKitDaemonBackendClass *klass);
static void     polkit_daemon_backend_init        (PolKitDaemonBackend      *seat);
static void     polkit_daemon_backend_finalize    (GObject     *object);

G_DEFINE_TYPE (PolKitDaemonBackend, polkit_daemon_backend, G_TYPE_OBJECT)

#define POLKIT_DAEMON_BACKEND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_DAEMON_BACKEND, PolKitDaemonBackendPrivate))

GQuark
polkit_daemon_backend_error_quark (void)
{
        static GQuark ret = 0;

        if (ret == 0) {
                ret = g_quark_from_static_string ("polkit_daemon_backend_error");
        }

        return ret;
}


#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
polkit_daemon_backend_error_get_type (void)
{
        static GType etype = 0;
        
        if (etype == 0)
        {
                static const GEnumValue values[] =
                        {
                                ENUM_ENTRY (POLKIT_DAEMON_BACKEND_ERROR_GENERAL, "GeneralError"),
                                { 0, 0, 0 }
                        };
                
                g_assert (POLKIT_DAEMON_BACKEND_NUM_ERRORS == G_N_ELEMENTS (values) - 1);
                
                etype = g_enum_register_static ("PolKitDaemonBackendError", values);
        }
        
        return etype;
}


static GObject *
polkit_daemon_backend_constructor (GType                  type,
                                            guint                  n_construct_properties,
                                            GObjectConstructParam *construct_properties)
{
        PolKitDaemonBackend      *daemon_backend;
        PolKitDaemonBackendClass *klass;

        klass = POLKIT_DAEMON_BACKEND_CLASS (g_type_class_peek (POLKIT_TYPE_DAEMON_BACKEND));

        daemon_backend = POLKIT_DAEMON_BACKEND (
                G_OBJECT_CLASS (polkit_daemon_backend_parent_class)->constructor (type,
                                                                                           n_construct_properties,
                                                                                           construct_properties));
        
        return G_OBJECT (daemon_backend);
}

static void
polkit_daemon_backend_class_init (PolKitDaemonBackendClass *klass)
{
        GObjectClass   *object_class = G_OBJECT_CLASS (klass);

        object_class->constructor = polkit_daemon_backend_constructor;
        object_class->finalize = polkit_daemon_backend_finalize;

        g_type_class_add_private (klass, sizeof (PolKitDaemonBackendPrivate));

        dbus_g_object_type_install_info (POLKIT_TYPE_DAEMON_BACKEND, &dbus_glib_polkit_daemon_backend_object_info);

        dbus_g_error_domain_register (POLKIT_DAEMON_BACKEND_ERROR, NULL, POLKIT_DAEMON_BACKEND_TYPE_ERROR);

}

static void
polkit_daemon_backend_init (PolKitDaemonBackend *daemon_backend)
{
        daemon_backend->priv = POLKIT_DAEMON_BACKEND_GET_PRIVATE (daemon_backend);

}

static void
polkit_daemon_backend_finalize (GObject *object)
{
        PolKitDaemonBackend *daemon_backend;

        g_return_if_fail (object != NULL);
        g_return_if_fail (POLKIT_IS_DAEMON_BACKEND (object));

        daemon_backend = POLKIT_DAEMON_BACKEND (object);

        g_return_if_fail (daemon_backend->priv != NULL);

        g_object_unref (daemon_backend->priv->system_bus_proxy);

        G_OBJECT_CLASS (polkit_daemon_backend_parent_class)->finalize (object);
}

static gboolean
register_daemon_backend (PolKitDaemonBackend *daemon_backend)
{
        DBusConnection *connection;
        GError *error = NULL;

        error = NULL;
        daemon_backend->priv->system_bus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (daemon_backend->priv->system_bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }
        connection = dbus_g_connection_get_connection (daemon_backend->priv->system_bus_connection);

        dbus_g_connection_register_g_object (daemon_backend->priv->system_bus_connection, "/", 
                                             G_OBJECT (daemon_backend));

        daemon_backend->priv->system_bus_proxy = dbus_g_proxy_new_for_name (daemon_backend->priv->system_bus_connection,
                                                                      DBUS_SERVICE_DBUS,
                                                                      DBUS_PATH_DBUS,
                                                                      DBUS_INTERFACE_DBUS);

        reset_killtimer ();

        return TRUE;

error:
        return FALSE;
}


PolKitDaemonBackend *
polkit_daemon_backend_new (gboolean _no_exit)
{
        GObject *object;
        gboolean res;

        no_exit = _no_exit;

        object = g_object_new (POLKIT_TYPE_DAEMON_BACKEND, NULL);

        res = register_daemon_backend (POLKIT_DAEMON_BACKEND (object));
        if (! res) {
                g_object_unref (object);
                return NULL;
        }

        return POLKIT_DAEMON_BACKEND (object);
}

/*--------------------------------------------------------------------------------------------------------------*/
/* exported methods */

gboolean
polkit_daemon_backend_hello (PolKitDaemonBackend   *daemon,
                             const char            *message,
                             DBusGMethodInvocation *context)
{
        char *s;

        s = g_strdup_printf ("You said '%s'", message);
        dbus_g_method_return (context, s);
        g_free (s);

        return TRUE;
}

/*--------------------------------------------------------------------------------------------------------------*/



gboolean
polkit_daemon_backend_get_policy_entries (PolKitDaemonBackend   *daemon,
                                          DBusGMethodInvocation *context)
{
        GPtrArray *a;
        PolKitPolicyCache *c;

        c = _polkit_policy_cache_new (PACKAGE_DATA_DIR "polkit-1/actions", TRUE, NULL);
        polkit_policy_cache_unref (c);

        a = g_ptr_array_new ();
        g_ptr_array_add (a, g_strdup ("foo"));
        g_ptr_array_add (a, g_strdup ("bar"));
        g_ptr_array_add (a, g_strdup ("baz"));

        g_ptr_array_add (a, NULL);
        dbus_g_method_return (context, a->pdata);

        g_ptr_array_foreach (a, (GFunc) g_free, NULL);
        g_ptr_array_free (a, TRUE);

        return TRUE;
}

/*--------------------------------------------------------------------------------------------------------------*/

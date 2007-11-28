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

#include <polkit/polkit.h>
#include <polkit/polkit-utils.h>
#include <polkit-dbus/polkit-dbus.h>

#include "polkit-daemon.h"

static gboolean no_exit = FALSE;

/*--------------------------------------------------------------------------------------------------------------*/
#include "polkit-daemon-glue.h"

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

struct PolKitDaemonPrivate
{
        DBusGConnection *system_bus_connection;
        DBusGProxy      *system_bus_proxy;
        PolKitContext   *pk_context;
        PolKitTracker   *pk_tracker;
};

static void     polkit_daemon_class_init  (PolKitDaemonClass *klass);
static void     polkit_daemon_init        (PolKitDaemon      *seat);
static void     polkit_daemon_finalize    (GObject     *object);

G_DEFINE_TYPE (PolKitDaemon, polkit_daemon, G_TYPE_OBJECT)

#define POLKIT_DAEMON_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_DAEMON, PolKitDaemonPrivate))

GQuark
polkit_daemon_error_quark (void)
{
        static GQuark ret = 0;

        if (ret == 0) {
                ret = g_quark_from_static_string ("polkit_daemon_error");
        }

        return ret;
}


#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
polkit_daemon_error_get_type (void)
{
        static GType etype = 0;
        
        if (etype == 0)
        {
                static const GEnumValue values[] =
                        {
                                ENUM_ENTRY (POLKIT_DAEMON_ERROR_GENERAL, "GeneralError"),
                                ENUM_ENTRY (POLKIT_DAEMON_ERROR_NOT_AUTHORIZED, "NotAuthorized"),
                                { 0, 0, 0 }
                        };
                
                g_assert (POLKIT_DAEMON_NUM_ERRORS == G_N_ELEMENTS (values) - 1);
                
                etype = g_enum_register_static ("PolKitDaemonError", values);
        }
        
        return etype;
}


static GObject *
polkit_daemon_constructor (GType                  type,
                                            guint                  n_construct_properties,
                                            GObjectConstructParam *construct_properties)
{
        PolKitDaemon      *daemon;
        PolKitDaemonClass *klass;

        klass = POLKIT_DAEMON_CLASS (g_type_class_peek (POLKIT_TYPE_DAEMON));

        daemon = POLKIT_DAEMON (
                G_OBJECT_CLASS (polkit_daemon_parent_class)->constructor (type,
                                                                                           n_construct_properties,
                                                                                           construct_properties));
        
        return G_OBJECT (daemon);
}

static void
polkit_daemon_class_init (PolKitDaemonClass *klass)
{
        GObjectClass   *object_class = G_OBJECT_CLASS (klass);

        object_class->constructor = polkit_daemon_constructor;
        object_class->finalize = polkit_daemon_finalize;

        g_type_class_add_private (klass, sizeof (PolKitDaemonPrivate));

        dbus_g_object_type_install_info (POLKIT_TYPE_DAEMON, &dbus_glib_polkit_daemon_object_info);

        dbus_g_error_domain_register (POLKIT_DAEMON_ERROR, NULL, POLKIT_DAEMON_TYPE_ERROR);

}

static void
polkit_daemon_init (PolKitDaemon *daemon)
{
        daemon->priv = POLKIT_DAEMON_GET_PRIVATE (daemon);

}

static void
polkit_daemon_finalize (GObject *object)
{
        PolKitDaemon *daemon;

        g_return_if_fail (object != NULL);
        g_return_if_fail (POLKIT_IS_DAEMON (object));

        daemon = POLKIT_DAEMON (object);

        g_return_if_fail (daemon->priv != NULL);

        g_object_unref (daemon->priv->system_bus_proxy);

        G_OBJECT_CLASS (polkit_daemon_parent_class)->finalize (object);
}

static gboolean
pk_io_watch_have_data (GIOChannel *channel, GIOCondition condition, gpointer user_data)
{
        int fd;
        PolKitContext *pk_context = user_data;
        fd = g_io_channel_unix_get_fd (channel);
        polkit_context_io_func (pk_context, fd);
        return TRUE;
}

static int 
pk_io_add_watch (PolKitContext *pk_context, int fd)
{
        guint id = 0;
        GIOChannel *channel;
        channel = g_io_channel_unix_new (fd);
        if (channel == NULL)
                goto out;
        id = g_io_add_watch (channel, G_IO_IN, pk_io_watch_have_data, pk_context);
        if (id == 0) {
                g_io_channel_unref (channel);
                goto out;
        }
        g_io_channel_unref (channel);
out:
        return id;
}

static void 
pk_io_remove_watch (PolKitContext *pk_context, int watch_id)
{
        g_source_remove (watch_id);
}

static DBusHandlerResult
_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
        PolKitDaemon *daemon = POLKIT_DAEMON (user_data);

        /*  pass NameOwnerChanged signals from the bus and ConsoleKit to PolKitTracker */
        if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged") ||
            (dbus_message_get_interface (message) != NULL &&
             g_str_has_prefix (dbus_message_get_interface (message), "org.freedesktop.ConsoleKit"))) {
                if (polkit_tracker_dbus_func (daemon->priv->pk_tracker, message)) {
                        /* Something has changed! TODO: emit D-Bus signal? */
                }
        }

        /* other filters might want to process this message too */
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static gboolean
register_daemon (PolKitDaemon *daemon)
{
        DBusConnection *connection;
        DBusError dbus_error;
        GError *error = NULL;

        daemon->priv->pk_context = polkit_context_new ();
        polkit_context_set_io_watch_functions (daemon->priv->pk_context, pk_io_add_watch, pk_io_remove_watch);
        if (!polkit_context_init (daemon->priv->pk_context, NULL)) {
                g_critical ("cannot initialize libpolkit");
                goto error;
        }

        error = NULL;
        daemon->priv->system_bus_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (daemon->priv->system_bus_connection == NULL) {
                if (error != NULL) {
                        g_critical ("error getting system bus: %s", error->message);
                        g_error_free (error);
                }
                goto error;
        }
        connection = dbus_g_connection_get_connection (daemon->priv->system_bus_connection);

        daemon->priv->pk_tracker = polkit_tracker_new ();
        polkit_tracker_set_system_bus_connection (daemon->priv->pk_tracker, connection);
        polkit_tracker_init (daemon->priv->pk_tracker);

        dbus_g_connection_register_g_object (daemon->priv->system_bus_connection, "/", 
                                             G_OBJECT (daemon));

        daemon->priv->system_bus_proxy = dbus_g_proxy_new_for_name (daemon->priv->system_bus_connection,
                                                                      DBUS_SERVICE_DBUS,
                                                                      DBUS_PATH_DBUS,
                                                                      DBUS_INTERFACE_DBUS);

        /* TODO FIXME: I'm pretty sure dbus-glib blows in a way that
         * we can't say we're interested in all signals from all
         * members on all interfaces for a given service... So we do
         * this..
         */

        dbus_error_init (&dbus_error);

        /* need to listen to NameOwnerChanged */
	dbus_bus_add_match (connection,
			    "type='signal'"
			    ",interface='"DBUS_INTERFACE_DBUS"'"
			    ",sender='"DBUS_SERVICE_DBUS"'"
			    ",member='NameOwnerChanged'",
			    &dbus_error);

        if (dbus_error_is_set (&dbus_error)) {
                g_warning ("Cannot add match rule: %s: %s", dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
                goto error;
        }

        /* need to listen to ConsoleKit signals */
	dbus_bus_add_match (connection,
			    "type='signal',sender='org.freedesktop.ConsoleKit'",
			    &dbus_error);

        if (dbus_error_is_set (&dbus_error)) {
                g_warning ("Cannot add match rule: %s: %s", dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
                goto error;
        }

        if (!dbus_connection_add_filter (connection, 
                                         _filter, 
                                         daemon, 
                                         NULL)) {
                g_warning ("Cannot add D-Bus filter: %s: %s", dbus_error.name, dbus_error.message);
                goto error;
        }        

        reset_killtimer ();

        return TRUE;

error:
        return FALSE;
}


PolKitDaemon *
polkit_daemon_new (gboolean _no_exit)
{
        GObject *object;
        gboolean res;

        no_exit = _no_exit;

        object = g_object_new (POLKIT_TYPE_DAEMON, NULL);

        res = register_daemon (POLKIT_DAEMON (object));
        if (! res) {
                g_object_unref (object);
                return NULL;
        }

        return POLKIT_DAEMON (object);
}

/*--------------------------------------------------------------------------------------------------------------*/
/* exported methods */

static PolKitCaller *
get_caller_from_context (PolKitDaemon *daemon, DBusGMethodInvocation *context)
{
        const char *sender;
        GError *error;
        DBusError dbus_error;
        PolKitCaller *pk_caller;

        sender = dbus_g_method_get_sender (context);
        dbus_error_init (&dbus_error);
        pk_caller = polkit_tracker_get_caller_from_dbus_name (daemon->priv->pk_tracker,
                                                              sender, 
                                                              &dbus_error);
        if (pk_caller == NULL) {
                error = g_error_new (POLKIT_DAEMON_ERROR,
                                     POLKIT_DAEMON_ERROR_GENERAL,
                                     "Error getting information about caller: %s: %s",
                                     dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
                dbus_g_method_return_error (context, error);
                g_error_free (error);
                return NULL;
        }

        return pk_caller;
}


/* takes ownership of pk_caller */
static gboolean
is_caller_authorized (PolKitDaemon          *daemon, 
                      const char            *action_id, 
                      PolKitCaller          *pk_caller, 
                      gboolean               revoke_if_one_shot,
                      DBusGMethodInvocation *context)
{
        gboolean ret;
        GError *error;
        PolKitCaller *pk_caller_who_wants_to_know;
        uid_t uid_caller;
        uid_t uid_caller_who_wants_to_know;
        PolKitAction *pk_action;
        PolKitResult pk_result;

        ret = FALSE;
        pk_caller_who_wants_to_know = NULL;

        pk_caller_who_wants_to_know = get_caller_from_context (daemon, context);
        if (pk_caller_who_wants_to_know == NULL) {
                goto out;
        }

        if (!polkit_caller_get_uid (pk_caller_who_wants_to_know, &uid_caller_who_wants_to_know))
                goto out;

        if (!polkit_caller_get_uid (pk_caller, &uid_caller))
                goto out;

        if (uid_caller_who_wants_to_know != uid_caller) {
                /* if the uid's are different, the caller who wants to know need to posses
                 * the org.freedesktop.policykit.read authorization 
                 */

                pk_action = polkit_action_new ();
                polkit_action_set_action_id (pk_action, "org.freedesktop.policykit.read");
                pk_result = polkit_context_is_caller_authorized (daemon->priv->pk_context, 
                                                                 pk_action, 
                                                                 pk_caller_who_wants_to_know, 
                                                                 FALSE,
                                                                 NULL);
                polkit_action_unref (pk_action);
                if (pk_result != POLKIT_RESULT_YES) {
                        error = g_error_new (POLKIT_DAEMON_ERROR,
                                             POLKIT_DAEMON_ERROR_NOT_AUTHORIZED,
                                             "uid %d is not authorized to know authorizations for uid %d "
                                             "(requires org.freedesktop.policykit.read)",
                                             uid_caller_who_wants_to_know, uid_caller);
                        dbus_g_method_return_error (context, error);
                        g_error_free (error);
                        goto out;
                }
        }

        pk_action = polkit_action_new ();
        polkit_action_set_action_id (pk_action, action_id);
        pk_result = polkit_context_is_caller_authorized (daemon->priv->pk_context, 
                                                         pk_action, 
                                                         pk_caller, 
                                                         revoke_if_one_shot,
                                                         NULL);
        polkit_action_unref (pk_action);

        dbus_g_method_return (context, polkit_result_to_string_representation (pk_result));

out:
        if (pk_caller_who_wants_to_know != NULL)
                polkit_caller_unref (pk_caller_who_wants_to_know);

        if (pk_caller != NULL)
                polkit_caller_unref (pk_caller);

        return ret;
}

gboolean
polkit_daemon_is_process_authorized (PolKitDaemon          *daemon,
                                     const char            *action_id, 
                                     guint32                pid,
                                     gboolean               revoke_if_one_shot,
                                     DBusGMethodInvocation *context)
{
        gboolean ret;
        DBusError dbus_error;
        GError *error;
        PolKitCaller *pk_caller;

        reset_killtimer ();

        ret = FALSE;
        pk_caller = NULL;

        dbus_error_init (&dbus_error);
        pk_caller = polkit_tracker_get_caller_from_pid (daemon->priv->pk_tracker, (pid_t) pid, &dbus_error);
        if (pk_caller == NULL) {
                error = g_error_new (POLKIT_DAEMON_ERROR,
                                     POLKIT_DAEMON_ERROR_GENERAL,
                                     "Error getting information about pid %d: %s: %s",
                                     pid,
                                     dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
                dbus_g_method_return_error (context, error);
                g_error_free (error);
                goto out;
        }

        ret = is_caller_authorized (daemon, action_id, pk_caller, revoke_if_one_shot, context);

out:
        return ret;
}

gboolean
polkit_daemon_is_system_bus_name_authorized (PolKitDaemon          *daemon,
                                             const char            *action_id, 
                                             const char            *system_bus_name,
                                             gboolean               revoke_if_one_shot,
                                             DBusGMethodInvocation *context)
{
        gboolean ret;
        DBusError dbus_error;
        GError *error;
        PolKitCaller *pk_caller;

        reset_killtimer ();

        ret = FALSE;
        pk_caller = NULL;

        if (!_pk_validate_unique_bus_name (system_bus_name)) {
                error = g_error_new (POLKIT_DAEMON_ERROR,
                                     POLKIT_DAEMON_ERROR_GENERAL,
                                     "Given system bus name is not a valid unique system bus name");
                dbus_g_method_return_error (context, error);
                g_error_free (error);
                goto out;
        }

        dbus_error_init (&dbus_error);
        pk_caller = polkit_tracker_get_caller_from_dbus_name (daemon->priv->pk_tracker, system_bus_name, &dbus_error);
        if (pk_caller == NULL) {
                error = g_error_new (POLKIT_DAEMON_ERROR,
                                     POLKIT_DAEMON_ERROR_GENERAL,
                                     "Error getting information about system bus name %s: %s: %s",
                                     system_bus_name,
                                     dbus_error.name, dbus_error.message);
                dbus_error_free (&dbus_error);
                dbus_g_method_return_error (context, error);
                g_error_free (error);
                goto out;
        }

        ret = is_caller_authorized (daemon, action_id, pk_caller, revoke_if_one_shot, context);

out:
        return ret;
}

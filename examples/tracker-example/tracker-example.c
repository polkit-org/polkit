/*
 * Small example of how to use the PolKitTracker class.
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <polkit-dbus/polkit-dbus.h>

/* Note, on purpose, there is little or no error checking done
 * anywhere in this program. Use at your own risk.
 */

static void
print_caller (PolKitTracker *pk_tracker, const char *dbus_name)
{
        DBusError error;
        PolKitCaller *caller;

        dbus_error_init (&error);

        caller = polkit_tracker_get_caller_from_dbus_name (pk_tracker, 
                                                           dbus_name,
                                                           &error);
        if (caller == NULL) {
                g_warning ("Error getting PolKitCaller for '%s': %s: %s",
                           dbus_name, error.name, error.message);
                dbus_error_free (&error);
        } else {
                /* got it; print it to stdout */
                printf ("\n");
                polkit_caller_debug (caller);
                polkit_caller_unref (caller);
        }
}

static DBusHandlerResult
filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
        PolKitTracker *pk_tracker = (PolKitTracker *) user_data;
        char *name;
        char *new_service_name;
        char *old_service_name;

        /*  pass NameOwnerChanged signals from the bus and ConsoleKit to PolKitTracker */
        if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged") ||
            g_str_has_prefix (dbus_message_get_interface (message), "org.freedesktop.ConsoleKit")) {
                polkit_tracker_dbus_func (pk_tracker, message);
        }

        /* handle calls into our test service */
        if (dbus_message_is_method_call (message, "dk.fubar.PolKitTestService", "Test")) {
                DBusMessage *reply;
                const char *reply_str = "Right back at y'all!";

                print_caller (pk_tracker, dbus_message_get_sender (message));

                reply = dbus_message_new_method_return (message);
                dbus_message_append_args (reply, 
                                          DBUS_TYPE_STRING, &reply_str,
                                          DBUS_TYPE_INVALID);
                dbus_connection_send (connection, reply, NULL);
                dbus_message_unref (reply);

                /* this one we do handle */
                return DBUS_HANDLER_RESULT_HANDLED;
        }

        /* other filters might want to process this message too */
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


int
main (int argc, char *argv[])
{
        DBusError error;
        DBusConnection *con;
        GMainLoop *loop;
        PolKitTracker *pk_tracker;

        /* This is needed to get something out of polkit_caller_debug() */
        g_setenv ("POLKIT_DEBUG", "1", TRUE);

        loop = g_main_loop_new (NULL, FALSE);

        dbus_error_init (&error);
        con = dbus_bus_get (DBUS_BUS_SYSTEM, &error);

        pk_tracker = polkit_tracker_new ();
        polkit_tracker_set_system_bus_connection (pk_tracker, con);
        polkit_tracker_init (pk_tracker);

        /* need to listen to NameOwnerChanged */
	dbus_bus_add_match (con,
			    "type='signal'"
			    ",interface='"DBUS_INTERFACE_DBUS"'"
			    ",sender='"DBUS_SERVICE_DBUS"'"
			    ",member='NameOwnerChanged'",
			    &error);

        /* need to listen to ConsoleKit signals */
	dbus_bus_add_match (con,
			    "type='signal',sender='org.freedesktop.ConsoleKit'",
			    &error);

        /* own a simple service */
        dbus_bus_request_name (con, "dk.fubar.PolKitTestService", DBUS_NAME_FLAG_REPLACE_EXISTING, &error);

        dbus_connection_add_filter (con, filter, pk_tracker, NULL);
        dbus_connection_setup_with_g_main (con, g_main_loop_get_context (loop));

        g_main_loop_run (loop);
        return 0;
}

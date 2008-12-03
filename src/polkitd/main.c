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

#include <polkit/polkit.h>
#include <polkitbackend/polkitbackend.h>

static PolkitAuthority *
get_authority_backend (void)
{
        /* TODO: use extension points etc. */
        return POLKIT_AUTHORITY (polkit_backend_local_new ());
}

int
main (int argc, char **argv)
{
        int ret;
        guint rn_ret;
        GError *error;
        GMainLoop *loop;
        EggDBusConnection *connection;
        PolkitAuthority *authority;

        ret = 1;

        g_type_init ();
        polkit_bindings_register_types (); /* TODO: use __attribute ((constructor)) */

        loop = g_main_loop_new (NULL, FALSE);
        connection = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

        error = NULL;
        if (!egg_dbus_bus_invoke_request_name (egg_dbus_connection_get_bus_proxy (connection),
                                               0, /* call flags */
                                               "org.freedesktop.PolicyKit1",
                                               0, /* flags */
                                               &rn_ret,
                                               NULL,
                                               &error)) {
                g_warning ("error: %s", error->message);
                g_error_free (error);
                goto out;
        }

        if (rn_ret != 1) {
                g_warning ("could not become primary name owner");
                goto out;
        }

        authority = get_authority_backend ();

        egg_dbus_connection_export_object (connection,
                                           G_OBJECT (authority),
                                           "/org/freedesktop/PolicyKit1/Authority");

        g_main_loop_run (loop);
        g_object_unref (authority);
        g_object_unref (connection);

        ret = 0;

 out:
        return ret;
}

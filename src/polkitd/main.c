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
                                         &error))
    {
      g_warning ("error: %s", error->message);
      g_error_free (error);
      goto out;
    }

  if (rn_ret != 1)
    {
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

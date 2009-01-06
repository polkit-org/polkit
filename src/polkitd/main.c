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
#include <polkit/polkitprivate.h>

#include <polkitbackend/polkitbackend.h>

static _PolkitAuthority *
get_authority_backend (void)
{
  PolkitBackendAuthority *authority;
  PolkitBackendServer *server;

  /* TODO: use extension points etc. */
  authority = polkit_backend_local_authority_new ();

  server = polkit_backend_server_new (authority);

  g_object_unref (authority);

  return _POLKIT_AUTHORITY (server);
}

int
main (int argc, char **argv)
{
  int ret;
  guint rn_ret;
  GError *error;
  GMainLoop *loop;
  EggDBusConnection *connection;
  _PolkitAuthority *authority;

  ret = 1;
  authority = NULL;
  connection = NULL;

  g_type_init ();

  loop = g_main_loop_new (NULL, FALSE);
  connection = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  error = NULL;
  if (!egg_dbus_bus_request_name_sync (egg_dbus_connection_get_bus (connection),
                                       EGG_DBUS_CALL_FLAGS_NONE,
                                       "org.freedesktop.PolicyKit1",
                                       EGG_DBUS_REQUEST_NAME_FLAGS_NONE,
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

  egg_dbus_connection_register_interface (connection,
                                          "/org/freedesktop/PolicyKit1/Authority",
                                          _POLKIT_TYPE_AUTHORITY,
                                          G_OBJECT (authority),
                                          G_TYPE_INVALID);

  g_main_loop_run (loop);

  ret = 0;

 out:
  if (authority != NULL)
    g_object_unref (authority);
  if (connection != NULL)
    g_object_unref (connection);
  return ret;
}

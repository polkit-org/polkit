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
#include <string.h>
#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>

#include "polkitbackendauthority.h"
#include "polkitbackendserver.h"

struct _PolkitBackendServer
{
  GObject parent_instance;

  PolkitBackendAuthority *authority;
};

struct _PolkitBackendServerClass
{
  GObjectClass parent_class;
};

static void authority_iface_init (_PolkitAuthorityIface *authority_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitBackendServer, polkit_backend_server, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (_POLKIT_TYPE_AUTHORITY, authority_iface_init)
                         );

static void
polkit_backend_server_init (PolkitBackendServer *local_server)
{
}

static void
polkit_backend_server_finalize (GObject *object)
{
  PolkitBackendServer *server;

  server = POLKIT_BACKEND_SERVER (object);

  g_object_unref (server->authority);
}

static void
polkit_backend_server_class_init (PolkitBackendServerClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_backend_server_finalize;
}

PolkitBackendServer *
polkit_backend_server_new (PolkitBackendAuthority *authority)
{
  PolkitBackendServer *server;

  server = POLKIT_BACKEND_SERVER (g_object_new (POLKIT_BACKEND_TYPE_SERVER, NULL));

  server->authority = g_object_ref (authority);

  return server;
}

static void
authority_handle_enumerate_actions (_PolkitAuthority        *instance,
                                    const gchar             *locale,
                                    EggDBusMethodInvocation *method_invocation)
{
  PolkitBackendServer *server = POLKIT_BACKEND_SERVER (instance);
  EggDBusArraySeq *array;
  GList *actions;
  GList *l;

  actions = polkit_backend_authority_enumerate_actions (server->authority, locale);

  array = egg_dbus_array_seq_new (_POLKIT_TYPE_ACTION_DESCRIPTION, NULL, NULL, NULL);

  for (l = actions; l != NULL; l = l->next)
    {
      PolkitActionDescription *ad = POLKIT_ACTION_DESCRIPTION (l->data);
      egg_dbus_array_seq_add (array, polkit_action_description_get_real (ad));
    }

  _polkit_authority_handle_enumerate_actions_finish (method_invocation, array);

  g_object_unref (array);

  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);
}

static void
authority_iface_init (_PolkitAuthorityIface *authority_iface)
{
  authority_iface->handle_enumerate_actions = authority_handle_enumerate_actions;
}

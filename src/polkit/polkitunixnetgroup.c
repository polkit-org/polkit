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
 * Author: Nikki VonHollen <vonhollen@google.com>
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include "polkitunixnetgroup.h"
#include "polkitidentity.h"
#include "polkiterror.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitunixnetgroup
 * @title: PolkitUnixNetgroup
 * @short_description: Unix netgroups
 *
 * An object representing a netgroup identity on a UNIX system.
 */

/**
 * PolkitUnixNetgroup:
 *
 * The #PolkitUnixNetgroup struct should not be accessed directly.
 */
struct _PolkitUnixNetgroup
{
  GObject parent_instance;

  gchar *name;
};

struct _PolkitUnixNetgroupClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_NAME,
};

static void identity_iface_init (PolkitIdentityIface *identity_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixNetgroup, polkit_unix_netgroup, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_IDENTITY, identity_iface_init)
                         );

static void
polkit_unix_netgroup_init (PolkitUnixNetgroup *net_group)
{
  net_group->name = NULL;
}

static void
polkit_unix_netgroup_finalize (GObject *object)
{
  PolkitUnixNetgroup *net_group = POLKIT_UNIX_NETGROUP (object);

  g_free(net_group->name);

  G_OBJECT_CLASS (polkit_unix_netgroup_parent_class)->finalize (object);
}

static void
polkit_unix_netgroup_get_property (GObject    *object,
                                guint       prop_id,
                                GValue     *value,
                                GParamSpec *pspec)
{
  PolkitUnixNetgroup *net_group = POLKIT_UNIX_NETGROUP (object);

  switch (prop_id)
    {
    case PROP_NAME:
      g_value_set_string (value, polkit_unix_netgroup_get_name (net_group));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_netgroup_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
  PolkitUnixNetgroup *net_group = POLKIT_UNIX_NETGROUP (object);

  switch (prop_id)
    {
    case PROP_NAME:
      polkit_unix_netgroup_set_name (net_group, g_value_get_string (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_netgroup_class_init (PolkitUnixNetgroupClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize     = polkit_unix_netgroup_finalize;
  gobject_class->get_property = polkit_unix_netgroup_get_property;
  gobject_class->set_property = polkit_unix_netgroup_set_property;

  /**
   * PolkitUnixNetgroup:name:
   *
   * The NIS netgroup name.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_NAME,
                                   g_param_spec_string ("name",
                                                        "Group Name",
                                                        "The NIS netgroup name",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

}

/**
 * polkit_unix_netgroup_get_name:
 * @group: A #PolkitUnixNetgroup.
 *
 * Gets the netgroup name for @group.
 *
 * Returns: A netgroup name string.
 */
const gchar *
polkit_unix_netgroup_get_name (PolkitUnixNetgroup *group)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_NETGROUP (group), NULL);
  return group->name;
}

/**
 * polkit_unix_netgroup_set_name:
 * @group: A #PolkitUnixNetgroup.
 * @name: A netgroup name.
 *
 * Sets @name for @group.
 */
void
polkit_unix_netgroup_set_name (PolkitUnixNetgroup *group,
                           const gchar * name)
{
  g_return_if_fail (POLKIT_IS_UNIX_NETGROUP (group));
  g_free(group->name);
  group->name = g_strdup(name);
}

/**
 * polkit_unix_netgroup_new:
 * @name: A netgroup name.
 *
 * Creates a new #PolkitUnixNetgroup object for @name.
 *
 * Returns: (transfer full): A #PolkitUnixNetgroup object. Free with g_object_unref().
 */
PolkitIdentity *
polkit_unix_netgroup_new (const gchar *name)
{
#ifndef HAVE_SETNETGRENT
  g_assert_not_reached();
#endif
  g_return_val_if_fail (name != NULL, NULL);
  return POLKIT_IDENTITY (g_object_new (POLKIT_TYPE_UNIX_NETGROUP,
                                       "name", name,
                                       NULL));
}

static guint
polkit_unix_netgroup_hash (PolkitIdentity *identity)
{
  PolkitUnixNetgroup *group;

  group = POLKIT_UNIX_NETGROUP (identity);

  return g_str_hash(group->name);
}

static gboolean
polkit_unix_netgroup_equal (PolkitIdentity *a,
                        PolkitIdentity *b)
{
  PolkitUnixNetgroup *group_a;
  PolkitUnixNetgroup *group_b;

  group_a = POLKIT_UNIX_NETGROUP (a);
  group_b = POLKIT_UNIX_NETGROUP (b);

  if (g_strcmp0(group_a->name, group_b->name) == 0)
    return TRUE;
  else
    return FALSE;
}

static gchar *
polkit_unix_netgroup_to_string (PolkitIdentity *identity)
{
  PolkitUnixNetgroup *group = POLKIT_UNIX_NETGROUP (identity);
  return g_strconcat("unix-netgroup:", group->name, NULL);
}

static void
identity_iface_init (PolkitIdentityIface *identity_iface)
{
  identity_iface->hash      = polkit_unix_netgroup_hash;
  identity_iface->equal     = polkit_unix_netgroup_equal;
  identity_iface->to_string = polkit_unix_netgroup_to_string;
}

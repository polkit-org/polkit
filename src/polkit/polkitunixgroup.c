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

#include <string.h>
#include <grp.h>
#include <errno.h>
#include "polkitunixgroup.h"
#include "polkitidentity.h"
#include "polkiterror.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitunixgroup
 * @title: PolkitUnixGroup
 * @short_description: Unix groups
 *
 * An object representing a group identity on a UNIX system.
 */

/**
 * PolkitUnixGroup:
 *
 * The #PolkitUnixGroup struct should not be accessed directly.
 */
struct _PolkitUnixGroup
{
  GObject parent_instance;

  gint gid;
};

struct _PolkitUnixGroupClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_GID,
};

static void identity_iface_init (PolkitIdentityIface *identity_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixGroup, polkit_unix_group, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_IDENTITY, identity_iface_init)
                         );

static void
polkit_unix_group_init (PolkitUnixGroup *unix_group)
{
  unix_group->gid = -1; /* (gid_t) -1 is not a valid GID under Linux */
}

static void
polkit_unix_group_get_property (GObject    *object,
                                guint       prop_id,
                                GValue     *value,
                                GParamSpec *pspec)
{
  PolkitUnixGroup *unix_group = POLKIT_UNIX_GROUP (object);

  switch (prop_id)
    {
    case PROP_GID:
      g_value_set_int (value, unix_group->gid);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_group_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
  PolkitUnixGroup *unix_group = POLKIT_UNIX_GROUP (object);
  gint val;

  switch (prop_id)
    {
    case PROP_GID:
      val = g_value_get_int (value);
      g_return_if_fail (val != -1);
      unix_group->gid = val;
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_group_class_init (PolkitUnixGroupClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_unix_group_get_property;
  gobject_class->set_property = polkit_unix_group_set_property;

  /**
   * PolkitUnixGroup:gid:
   *
   * The UNIX group id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_GID,
                                   g_param_spec_int ("gid",
                                                     "Group ID",
                                                     "The UNIX group ID",
                                                     G_MININT,
                                                     G_MAXINT,
                                                     -1,
                                                     G_PARAM_CONSTRUCT |
                                                     G_PARAM_READWRITE |
                                                     G_PARAM_STATIC_NAME |
                                                     G_PARAM_STATIC_BLURB |
                                                     G_PARAM_STATIC_NICK));

}

/**
 * polkit_unix_group_get_gid:
 * @group: A #PolkitUnixGroup.
 *
 * Gets the UNIX group id for @group.
 *
 * Returns: A UNIX group id.
 */
gint
polkit_unix_group_get_gid (PolkitUnixGroup *group)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_GROUP (group), -1);
  return group->gid;
}

/**
 * polkit_unix_group_set_gid:
 * @group: A #PolkitUnixGroup.
 * @gid: A UNIX group id.
 *
 * Sets @gid for @group.
 */
void
polkit_unix_group_set_gid (PolkitUnixGroup *group,
                           gint gid)
{
  g_return_if_fail (POLKIT_IS_UNIX_GROUP (group));
  g_return_if_fail (gid != -1);
  group->gid = gid;
}

/**
 * polkit_unix_group_new:
 * @gid: A UNIX group id.
 *
 * Creates a new #PolkitUnixGroup object for @gid.
 *
 * Returns: (transfer full): A #PolkitUnixGroup object. Free with g_object_unref().
 */
PolkitIdentity *
polkit_unix_group_new (gint gid)
{
  g_return_val_if_fail (gid != -1, NULL);

  return POLKIT_IDENTITY (g_object_new (POLKIT_TYPE_UNIX_GROUP,
                                       "gid", gid,
                                       NULL));
}

/**
 * polkit_unix_group_new_for_name:
 * @name: A UNIX group name.
 * @error: Return location for error.
 *
 * Creates a new #PolkitUnixGroup object for a group with the group name
 * @name.
 *
 * Returns: (transfer full) (allow-none): A #PolkitUnixGroup object or %NULL if @error
 * is set.
 */
PolkitIdentity *
polkit_unix_group_new_for_name (const gchar    *name,
                                GError        **error)
{
  struct group *group;
  PolkitIdentity *identity;

  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  identity = NULL;

  group = getgrnam (name);
  if (group == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "No UNIX group with name %s: %s",
                   name,
                   g_strerror (errno));
      goto out;
    }

  identity = polkit_unix_group_new (group->gr_gid);

 out:
  return identity;
}

static guint
polkit_unix_group_hash (PolkitIdentity *identity)
{
  PolkitUnixGroup *group;

  group = POLKIT_UNIX_GROUP (identity);

  return g_direct_hash (GINT_TO_POINTER (((gint) (group->gid)) * 2 + 1));
}

static gboolean
polkit_unix_group_equal (PolkitIdentity *a,
                        PolkitIdentity *b)
{
  PolkitUnixGroup *group_a;
  PolkitUnixGroup *group_b;

  group_a = POLKIT_UNIX_GROUP (a);
  group_b = POLKIT_UNIX_GROUP (b);

  return group_a->gid == group_b->gid;
}

static gchar *
polkit_unix_group_to_string (PolkitIdentity *identity)
{
  PolkitUnixGroup *group = POLKIT_UNIX_GROUP (identity);
  struct group *gr;

  gr = getgrgid (group->gid);

  if (gr == NULL)
    return g_strdup_printf ("unix-group:%d", group->gid);
  else
    return g_strdup_printf ("unix-group:%s", gr->gr_name);
}

static void
identity_iface_init (PolkitIdentityIface *identity_iface)
{
  identity_iface->hash      = polkit_unix_group_hash;
  identity_iface->equal     = polkit_unix_group_equal;
  identity_iface->to_string = polkit_unix_group_to_string;
}

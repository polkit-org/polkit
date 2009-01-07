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
#include "polkitunixgroup.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitunixgroup
 * @title: PolkitUnixGroup
 * @short_description: Unix groups
 *
 * Encapsulates a UNIX group.
 */

struct _PolkitUnixGroup
{
  GObject parent_instance;

  gid_t gid;
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

static void subject_iface_init (PolkitSubjectIface *subject_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixGroup, polkit_unix_group, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_unix_group_init (PolkitUnixGroup *unix_group)
{
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
      g_value_set_uint (value, unix_group->gid);
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

  switch (prop_id)
    {
    case PROP_GID:
      unix_group->gid = g_value_get_uint (value);
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
                                   g_param_spec_uint ("gid",
                                                      "Group ID",
                                                      "The UNIX group ID",
                                                      0,
                                                      G_MAXUINT,
                                                      0,
                                                      G_PARAM_CONSTRUCT |
                                                      G_PARAM_READWRITE |
                                                      G_PARAM_STATIC_NAME |
                                                      G_PARAM_STATIC_BLURB |
                                                      G_PARAM_STATIC_NICK));

}

gid_t
polkit_unix_group_get_gid (PolkitUnixGroup *group)
{
  return group->gid;
}

void
polkit_unix_group_set_gid (PolkitUnixGroup *group,
                          gid_t gid)
{
  group->gid = gid;
}

PolkitSubject *
polkit_unix_group_new (gid_t gid)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_GROUP,
                                       "gid", gid,
                                       NULL));
}

static gboolean
polkit_unix_group_equal (PolkitSubject *a,
                        PolkitSubject *b)
{
  PolkitUnixGroup *group_a;
  PolkitUnixGroup *group_b;

  group_a = POLKIT_UNIX_GROUP (a);
  group_b = POLKIT_UNIX_GROUP (b);

  return group_a->gid == group_b->gid;
}

static gchar *
polkit_unix_group_to_string (PolkitSubject *subject)
{
  PolkitUnixGroup *group = POLKIT_UNIX_GROUP (subject);
  struct group *gr;

  gr = getgrgid (group->gid);

  if (gr == NULL)
    return g_strdup_printf ("unix-group:%d", group->gid);
  else
    return g_strdup_printf ("unix-group:%s", gr->gr_name);
}

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->equal     = polkit_unix_group_equal;
  subject_iface->to_string = polkit_unix_group_to_string;
}

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
#include "polkitsystembusname.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitsystembusname
 * @title: PolkitSystemBusName
 * @short_description: Unique system bus name
 *
 * Encapsulates a process with a unique name on the system bus.
 */

struct _PolkitSystemBusName
{
  GObject parent_instance;

  gchar *name;
};

struct _PolkitSystemBusNameClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_NAME,
};

static void subject_iface_init (PolkitSubjectIface *subject_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitSystemBusName, polkit_system_bus_name, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_system_bus_name_init (PolkitSystemBusName *system_bus_name)
{
}

static void
polkit_system_bus_name_finalize (GObject *object)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (object);

  g_free (system_bus_name->name);

  if (G_OBJECT_CLASS (polkit_system_bus_name_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_system_bus_name_parent_class)->finalize (object);
}

static void
polkit_system_bus_name_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (object);

  switch (prop_id)
    {
    case PROP_NAME:
      g_value_set_string (value, system_bus_name->name);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_system_bus_name_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (object);

  switch (prop_id)
    {
    case PROP_NAME:
      polkit_system_bus_name_set_name (system_bus_name, g_value_get_string (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_system_bus_name_class_init (PolkitSystemBusNameClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_system_bus_name_get_property;
  gobject_class->set_property = polkit_system_bus_name_set_property;
  gobject_class->finalize     = polkit_system_bus_name_finalize;

  /**
   * PolkitSystemBusName:name:
   *
   * The unique name on the system message bus.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_NAME,
                                   g_param_spec_string ("name",
                                                        "Name",
                                                        "The unique name on the system message bus",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

}

const gchar *
polkit_system_bus_name_get_name (PolkitSystemBusName *system_bus_name)
{
  return system_bus_name->name;
}

void
polkit_system_bus_name_set_name (PolkitSystemBusName *system_bus_name,
                                 const gchar         *name)
{
  g_free (system_bus_name->name);
  system_bus_name->name = g_strdup (name);
}

PolkitSubject *
polkit_system_bus_name_new (const gchar *name)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_SYSTEM_BUS_NAME,
                                       "name", name,
                                       NULL));
}

static gboolean
polkit_system_bus_name_equal (PolkitSubject *a,
                              PolkitSubject *b)
{
  PolkitSystemBusName *name_a;
  PolkitSystemBusName *name_b;

  name_a = POLKIT_SYSTEM_BUS_NAME (a);
  name_b = POLKIT_SYSTEM_BUS_NAME (b);

  return strcmp (name_a->name, name_b->name) == 0;
}

static gchar *
polkit_system_bus_name_to_string (PolkitSubject *subject)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (subject);

  return g_strdup_printf ("system-bus-name:%s", system_bus_name->name);
}

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->equal     = polkit_system_bus_name_equal;
  subject_iface->to_string = polkit_system_bus_name_to_string;
}

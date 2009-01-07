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
#include "polkitactiondescription.h"
#include "_polkitactiondescription.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitactiondescription
 * @title: PolkitActionDescription
 * @short_description: Actions
 *
 * Encapsulates an action.
 */

struct _PolkitActionDescription
{
  GObject parent_instance;

  _PolkitActionDescription *real;

  gchar **annotation_keys;

  GIcon *icon;
};

struct _PolkitActionDescriptionClass
{
  GObjectClass parent_class;
};

G_DEFINE_TYPE (PolkitActionDescription, polkit_action_description, G_TYPE_OBJECT);

static void
polkit_action_description_init (PolkitActionDescription *action_description)
{
}

static void
polkit_action_description_finalize (GObject *object)
{
  PolkitActionDescription *action_description;

  action_description = POLKIT_ACTION_DESCRIPTION (object);

  g_object_unref (action_description->real);

  g_strfreev (action_description->annotation_keys);

  if (action_description->icon != NULL)
    g_object_unref (action_description->icon);
}

static void
polkit_action_description_class_init (PolkitActionDescriptionClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_action_description_finalize;
}

PolkitActionDescription *
polkit_action_description_new_for_real (_PolkitActionDescription *real)
{
  PolkitActionDescription *action_description;

  action_description = POLKIT_ACTION_DESCRIPTION (g_object_new (POLKIT_TYPE_ACTION_DESCRIPTION, NULL));
  action_description->real = g_object_ref (real);

  return action_description;
}

_PolkitActionDescription *
polkit_action_description_get_real (PolkitActionDescription *action_description)
{
  return g_object_ref (action_description->real);
}

const gchar  *
polkit_action_description_get_action_id (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_action_id (action_description->real);
}

const gchar  *
polkit_action_description_get_description (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_description (action_description->real);
}

const gchar  *
polkit_action_description_get_message (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_message (action_description->real);
}

const gchar  *
polkit_action_description_get_vendor_name (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_vendor_name (action_description->real);
}

const gchar  *
polkit_action_description_get_vendor_url (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_vendor_url (action_description->real);
}

GIcon *
polkit_action_description_get_icon (PolkitActionDescription *action_description)
{
  const gchar *icon_name;
  GError *error;

  if (action_description->icon != NULL)
    goto out;

  icon_name = _polkit_action_description_get_icon_name (action_description->real);
  if (icon_name == NULL || strlen (icon_name) == 0)
    goto out;

  error = NULL;
  action_description->icon = g_icon_new_for_string (icon_name, &error);
  if (action_description->icon == NULL)
    {
      g_warning ("polkit_action_description_get_icon: %s", error->message);
      g_error_free (error);
    }

 out:
  return action_description->icon;
}

const gchar *
polkit_action_description_get_annotation (PolkitActionDescription *action_description,
                                          const gchar             *key)
{
  EggDBusHashMap *annotations;

  annotations = _polkit_action_description_get_annotations (action_description->real);

  return egg_dbus_hash_map_lookup (annotations, key);
}

static gboolean
collect_keys (EggDBusHashMap *hash_map,
              gpointer        key,
              gpointer        value,
              gpointer        user_data)
{
  GPtrArray *p = user_data;

  g_ptr_array_add (p, g_strdup (key));

  return FALSE;
}


const gchar * const *
polkit_action_description_get_annotation_keys (PolkitActionDescription *action_description)
{
  EggDBusHashMap *annotations;
  GPtrArray *p;

  if (action_description->annotation_keys != NULL)
    goto out;

  annotations = _polkit_action_description_get_annotations (action_description->real);

  p = g_ptr_array_new ();

  egg_dbus_hash_map_foreach (annotations, collect_keys, p);

  g_ptr_array_add (p, NULL);

  action_description->annotation_keys = (gchar **) g_ptr_array_free (p, FALSE);

 out:
  return (const gchar * const *) action_description->annotation_keys;
}


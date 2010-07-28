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
#include "polkitimplicitauthorization.h"
#include "polkitactiondescription.h"
#include "_polkitactiondescription.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitactiondescription
 * @title: PolkitActionDescription
 * @short_description: Description of Actions
 *
 * Object used to encapsulate a registered action.
 */

/**
 * PolkitActionDescription:
 *
 * The #PolkitActionDescription struct should not be accessed directly.
 */
struct _PolkitActionDescription
{
  GObject parent_instance;

  _PolkitActionDescription *real;

  gchar **annotation_keys;
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

  if (action_description->real != NULL)
    g_object_unref (action_description->real);

  g_strfreev (action_description->annotation_keys);

  if (G_OBJECT_CLASS (polkit_action_description_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_action_description_parent_class)->finalize (object);
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

/**
 * polkit_action_description_get_action_id:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the action id for @action_description.
 *
 * Returns: A string owned by @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_action_id (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_action_id (action_description->real);
}

/**
 * polkit_action_description_get_description:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the description used for @action_description.
 *
 * Returns: A string owned by @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_description (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_description (action_description->real);
}

/**
 * polkit_action_description_get_message:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the message used for @action_description.
 *
 * Returns: A string owned by @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_message (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_message (action_description->real);
}

/**
 * polkit_action_description_get_vendor_name:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the vendor name for @action_description, if any.
 *
 * Returns: %NULL if there is no vendor, otherwise a string owned by
 * @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_vendor_name (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_vendor_name (action_description->real);
}

/**
 * polkit_action_description_get_vendor_url:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the vendor URL for @action_description, if any.
 *
 * Returns: %NULL if there is no vendor URL, otherwise a string owned
 * by @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_vendor_url (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_vendor_url (action_description->real);
}

/**
 * polkit_action_description_get_implicit_any:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the implicit authorization for @action_description used for
 * any subject.
 *
 * Returns: A value from the #PolkitImplicitAuthorization enumeration.
 */
PolkitImplicitAuthorization
polkit_action_description_get_implicit_any (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_implicit_any (action_description->real);
}

/**
 * polkit_action_description_get_implicit_inactive:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the implicit authorization for @action_description used for
 * subjects in inactive sessions on a local console.
 *
 * Returns: A value from the #PolkitImplicitAuthorization enumeration.
 */
PolkitImplicitAuthorization
polkit_action_description_get_implicit_inactive (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_implicit_inactive (action_description->real);
}

/**
 * polkit_action_description_get_implicit_active:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the implicit authorization for @action_description used for
 * subjects in active sessions on a local console.
 *
 * Returns: A value from the #PolkitImplicitAuthorization enumeration.
 */
PolkitImplicitAuthorization
polkit_action_description_get_implicit_active (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_implicit_active (action_description->real);
}


/**
 * polkit_action_description_get_icon_name:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the icon name for @action_description, if any.
 *
 * Returns: %NULL if there is no icon for @action, otherwise the icon
 * name owned by @action_description. Do not free.
 */
const gchar *
polkit_action_description_get_icon_name (PolkitActionDescription *action_description)
{
  return _polkit_action_description_get_icon_name (action_description->real);
}

/**
 * polkit_action_description_get_annotation:
 * @action_description: A #PolkitActionDescription.
 * @key: An annotation key.
 *
 * Get the value of the annotation with @key.
 *
 * Returns: %NULL if there is no annoation with @key, otherwise the
 * annotation value owned by @action_description. Do not free.
 */
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


/**
 * polkit_action_description_get_annotation_keys:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the keys of annotations defined in @action_description.
 *
 * Returns: The annotation keys owned by @action_description. Do not free.
 */
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

PolkitActionDescription *
polkit_action_description_new_for_gvariant (GVariant *value)
{
  PolkitActionDescription *action_description;
  GVariantIter iter;
  const gchar *action_id;
  const gchar *description;
  const gchar *message;
  const gchar *vendor_name;
  const gchar *vendor_url;
  const gchar *icon_name;
  PolkitImplicitAuthorization implicit_any;
  PolkitImplicitAuthorization implicit_inactive;
  PolkitImplicitAuthorization implicit_active;
  GVariant *annotations_dict;
  gchar *a_key;
  gchar *a_value;
  EggDBusHashMap *hm;

  action_description = POLKIT_ACTION_DESCRIPTION (g_object_new (POLKIT_TYPE_ACTION_DESCRIPTION, NULL));
  g_variant_get (value,
                 "(&s&s&s&s&s&suuu@a{ss})",
                 &action_id,
                 &description,
                 &message,
                 &vendor_name,
                 &vendor_url,
                 &icon_name,
                 &implicit_any,
                 &implicit_inactive,
                 &implicit_active,
                 &annotations_dict);
  hm = egg_dbus_hash_map_new (G_TYPE_STRING, g_free, G_TYPE_STRING, g_free);
  g_variant_iter_init (&iter, annotations_dict);
  while (g_variant_iter_next (&iter, "{ss}", &a_key, &a_value))
    egg_dbus_hash_map_insert (hm, a_key, a_value);
  g_variant_unref (annotations_dict);

  action_description->real = _polkit_action_description_new (action_id, description, message, vendor_name, vendor_url, icon_name, implicit_any, implicit_inactive, implicit_active, hm);
  g_object_unref (hm);

  return action_description;
}

static gboolean
add_annotation (EggDBusHashMap *hash_map,
                gpointer        key,
                gpointer        value,
                gpointer        user_data)
{
  GVariantBuilder *builder = user_data;

  g_variant_builder_add (builder, "{ss}", key, value);

  return FALSE;
}

GVariant *
polkit_action_description_to_gvariant (PolkitActionDescription *action_description)
{
  GVariant *value;
  GVariantBuilder builder;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

  egg_dbus_hash_map_foreach (_polkit_action_description_get_annotations (action_description->real),
                             add_annotation,
                             &builder);

  /* TODO: note 'foo ? : ""' is a gcc specific extension (it's a short-hand for 'foo ? foo : ""') */
  value = g_variant_new ("(ssssssuuua{ss})",
                         _polkit_action_description_get_action_id (action_description->real) ? : "",
                         _polkit_action_description_get_description (action_description->real) ? : "",
                         _polkit_action_description_get_message (action_description->real) ? : "",
                         _polkit_action_description_get_vendor_name (action_description->real) ? : "",
                         _polkit_action_description_get_vendor_url (action_description->real) ? : "",
                         _polkit_action_description_get_icon_name (action_description->real) ? : "",
                         _polkit_action_description_get_implicit_any (action_description->real),
                         _polkit_action_description_get_implicit_inactive (action_description->real),
                         _polkit_action_description_get_implicit_active (action_description->real),
                         &builder);

  return value;
}

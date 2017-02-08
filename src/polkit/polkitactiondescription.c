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
  gchar *action_id;
  gchar *description;
  gchar *message;
  gchar *vendor_name;
  gchar *vendor_url;
  gchar *icon_name;
  PolkitImplicitAuthorization implicit_any;
  PolkitImplicitAuthorization implicit_inactive;
  PolkitImplicitAuthorization implicit_active;
  GHashTable *annotations;
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
  action_description->annotations = g_hash_table_new_full (g_str_hash,
                                                           g_str_equal,
                                                           g_free,
                                                           g_free);
}

static void
polkit_action_description_finalize (GObject *object)
{
  PolkitActionDescription *action_description;

  action_description = POLKIT_ACTION_DESCRIPTION (object);

  g_free (action_description->action_id);
  g_free (action_description->description);
  g_free (action_description->message);
  g_free (action_description->vendor_name);
  g_free (action_description->vendor_url);
  g_free (action_description->icon_name);
  g_hash_table_unref (action_description->annotations);
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
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->action_id;
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
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->description;
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
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->message;
}

/**
 * polkit_action_description_get_vendor_name:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the vendor name for @action_description, if any.
 *
 * Returns: A string owned by @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_vendor_name (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->vendor_name;
}

/**
 * polkit_action_description_get_vendor_url:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the vendor URL for @action_description, if any.
 *
 * Returns: A string owned by @action_description. Do not free.
 */
const gchar  *
polkit_action_description_get_vendor_url (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->vendor_url;
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
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), 0);
  return action_description->implicit_any;
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
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), 0);
  return action_description->implicit_inactive;
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
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), 0);
  return action_description->implicit_active;
}


/**
 * polkit_action_description_get_icon_name:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the icon name for @action_description, if any.
 *
 * Returns: A string owned by @action_description. Do not free.
 */
const gchar *
polkit_action_description_get_icon_name (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->icon_name;
}

/**
 * polkit_action_description_get_annotation:
 * @action_description: A #PolkitActionDescription.
 * @key: An annotation key.
 *
 * Get the value of the annotation with @key.
 *
 * Returns: (allow-none): %NULL if there is no annoation with @key,
 * otherwise the annotation value owned by @action_description. Do not
 * free.
 */
const gchar *
polkit_action_description_get_annotation (PolkitActionDescription *action_description,
                                          const gchar             *key)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return g_hash_table_lookup (action_description->annotations, key);
}

/**
 * polkit_action_description_get_annotation_keys:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the keys of annotations defined in @action_description.
 *
 * Returns: (transfer none): The annotation keys owned by @action_description. Do not free.
 */
const gchar * const *
polkit_action_description_get_annotation_keys (PolkitActionDescription *action_description)
{
  GPtrArray *p;
  GHashTableIter iter;
  const gchar *key;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);

  if (action_description->annotation_keys != NULL)
    goto out;

  p = g_ptr_array_new ();

  g_hash_table_iter_init (&iter, action_description->annotations);
  while (g_hash_table_iter_next (&iter, (gpointer) &key, NULL))
    g_ptr_array_add (p, g_strdup (key));

  g_ptr_array_add (p, NULL);
  action_description->annotation_keys = (gchar **) g_ptr_array_free (p, FALSE);

 out:
  return (const gchar * const *) action_description->annotation_keys;
}

PolkitActionDescription *
polkit_action_description_new (const gchar                 *action_id,
                               const gchar                 *description,
                               const gchar                 *message,
                               const gchar                 *vendor_name,
                               const gchar                 *vendor_url,
                               const gchar                 *icon_name,
                               PolkitImplicitAuthorization  implicit_any,
                               PolkitImplicitAuthorization  implicit_inactive,
                               PolkitImplicitAuthorization  implicit_active,
                               GHashTable                  *annotations)
{
  PolkitActionDescription *ret;
  g_return_val_if_fail (annotations != NULL, NULL);
  ret = POLKIT_ACTION_DESCRIPTION (g_object_new (POLKIT_TYPE_ACTION_DESCRIPTION, NULL));
  ret->action_id = g_strdup (action_id);
  ret->description = g_strdup (description);
  ret->message = g_strdup (message);
  ret->vendor_name = g_strdup (vendor_name);
  ret->vendor_url = g_strdup (vendor_url);
  ret->icon_name = g_strdup (icon_name);
  ret->implicit_any = implicit_any;
  ret->implicit_inactive = implicit_inactive;
  ret->implicit_active = implicit_active;
  if (ret->annotations != NULL)
    g_hash_table_unref (ret->annotations);
  ret->annotations = g_hash_table_ref (annotations);
  return ret;
}

PolkitActionDescription *
polkit_action_description_new_for_gvariant (GVariant *value)
{
  PolkitActionDescription *action_description;
  GVariantIter iter;
  GVariant *annotations_dict;
  gchar *a_key;
  gchar *a_value;

  action_description = POLKIT_ACTION_DESCRIPTION (g_object_new (POLKIT_TYPE_ACTION_DESCRIPTION, NULL));
  g_variant_get (value,
                 "(ssssssuuu@a{ss})",
                 &action_description->action_id,
                 &action_description->description,
                 &action_description->message,
                 &action_description->vendor_name,
                 &action_description->vendor_url,
                 &action_description->icon_name,
                 &action_description->implicit_any,
                 &action_description->implicit_inactive,
                 &action_description->implicit_active,
                 &annotations_dict);
  g_variant_iter_init (&iter, annotations_dict);
  while (g_variant_iter_next (&iter, "{ss}", &a_key, &a_value))
    g_hash_table_insert (action_description->annotations, a_key, a_value); /* adopts a_key and a_value */
  g_variant_unref (annotations_dict);

  return action_description;
}

/* Note that this returns a floating value. */
GVariant *
polkit_action_description_to_gvariant (PolkitActionDescription *action_description)
{
  GVariantBuilder builder;
  GHashTableIter iter;
  const gchar *a_key;
  const gchar *a_value;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));

  g_hash_table_iter_init (&iter, action_description->annotations);
  while (g_hash_table_iter_next (&iter, (gpointer) &a_key, (gpointer) &a_value))
    g_variant_builder_add (&builder, "{ss}", a_key, a_value);

  /* TODO: note 'foo ? : ""' is a gcc specific extension (it's a short-hand for 'foo ? foo : ""') */
  return g_variant_new ("(ssssssuuua{ss})",
                        action_description->action_id ? : "",
                        action_description->description ? : "",
                        action_description->message ? : "",
                        action_description->vendor_name ? : "",
                        action_description->vendor_url ? : "",
                        action_description->icon_name ? : "",
                        action_description->implicit_any,
                        action_description->implicit_inactive,
                        action_description->implicit_active,
                        &builder);
}

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
#include "polkitdetails.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitdetails
 * @title: PolkitDetails
 * @short_description: Object used for passing details
 * @stability: Stable
 *
 * An object used for passing details around.
 */

/**
 * PolkitDetails:
 *
 * The #PolkitDetails struct should not be accessed directly.
 */
struct _PolkitDetails
{
  GObject parent_instance;

  GHashTable *hash;
};

struct _PolkitDetailsClass
{
  GObjectClass parent_class;
};

G_DEFINE_TYPE (PolkitDetails, polkit_details, G_TYPE_OBJECT);

static void
polkit_details_init (PolkitDetails *details)
{
}

static void
polkit_details_finalize (GObject *object)
{
  PolkitDetails *details;

  details = POLKIT_DETAILS (object);

  if (details->hash != NULL)
    g_hash_table_unref (details->hash);

  if (G_OBJECT_CLASS (polkit_details_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_details_parent_class)->finalize (object);
}

static void
polkit_details_class_init (PolkitDetailsClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_details_finalize;
}

/**
 * polkit_details_new:
 *
 * Creates a new #PolkitDetails object.
 *
 * Returns: A #PolkitDetails object. Free with g_object_unref().
 */
PolkitDetails *
polkit_details_new (void)
{
  PolkitDetails *details;

  details = POLKIT_DETAILS (g_object_new (POLKIT_TYPE_DETAILS, NULL));

  return details;
}

/* private */
static PolkitDetails *
polkit_details_new_for_hash (GHashTable *hash)
{
  PolkitDetails *details;

  details = POLKIT_DETAILS (g_object_new (POLKIT_TYPE_DETAILS, NULL));
  if (hash != NULL)
    details->hash = g_hash_table_ref (hash);

  return details;
}

/**
 * polkit_details_lookup:
 * @details: A #PolkitDetails.
 * @key: A key.
 *
 * Gets the value for @key on @details.
 *
 * Returns: (allow-none): %NULL if there is no value for @key, otherwise a string owned by @details.
 */
const gchar *
polkit_details_lookup (PolkitDetails *details,
                       const gchar   *key)
{
  g_return_val_if_fail (POLKIT_IS_DETAILS (details), NULL);
  g_return_val_if_fail (key != NULL, NULL);
  if (details->hash == NULL)
    return NULL;
  else
    return g_hash_table_lookup (details->hash, key);
}

/**
 * polkit_details_insert:
 * @details: A #PolkitDetails.
 * @key: A key.
 * @value: (allow-none): A value.
 *
 * Inserts a copy of @key and @value on @details.
 *
 * If @value is %NULL, the key will be removed.
 */
void
polkit_details_insert (PolkitDetails *details,
                       const gchar   *key,
                       const gchar   *value)
{
  g_return_if_fail (POLKIT_IS_DETAILS (details));
  g_return_if_fail (key != NULL);
  if (details->hash == NULL)
    details->hash = g_hash_table_new_full (g_str_hash,
                                           g_str_equal,
                                           g_free,
                                           g_free);
  if (value != NULL)
    g_hash_table_insert (details->hash, g_strdup (key), g_strdup (value));
  else
    g_hash_table_remove (details->hash, key);
}

/**
 * polkit_details_get_keys:
 * @details: A #PolkitDetails.
 *
 * Gets a list of all keys on @details.
 *
 * Returns: (transfer full) (allow-none): %NULL if there are no keys
 * otherwise an array of strings that should be freed with
 * g_strfreev().
 */
gchar **
polkit_details_get_keys (PolkitDetails *details)
{
  GList *keys, *l;
  gchar **ret;
  guint n;

  g_return_val_if_fail (POLKIT_IS_DETAILS (details), NULL);

  if (details->hash == NULL)
    return NULL;

  keys = g_hash_table_get_keys (details->hash);
  ret = g_new0 (gchar*, g_list_length (keys) + 1);
  for (l = keys, n = 0; l != NULL; l = l->next, n++)
    ret[n] = g_strdup (l->data);

  g_list_free (keys);

  return ret;
}

/* Note that this returns a floating value. */
GVariant *
polkit_details_to_gvariant (PolkitDetails *details)
{
  GVariantBuilder builder;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{ss}"));
  if (details != NULL && details->hash != NULL)
    {
      GHashTableIter hash_iter;
      const gchar *key;
      const gchar *value;

      g_hash_table_iter_init (&hash_iter, details->hash);
      while (g_hash_table_iter_next (&hash_iter, (gpointer) &key, (gpointer) &value))
        g_variant_builder_add (&builder, "{ss}", key, value);
    }
  return g_variant_builder_end (&builder);
}

PolkitDetails *
polkit_details_new_for_gvariant (GVariant *value)
{
  PolkitDetails *ret;
  GHashTable *hash;
  GVariantIter iter;
  gchar *hash_key;
  gchar *hash_value;

  hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  g_variant_iter_init (&iter, value);
  while (g_variant_iter_next (&iter, "{ss}", &hash_key, &hash_value))
    g_hash_table_insert (hash, hash_key, hash_value);
  ret = polkit_details_new_for_hash (hash);
  g_hash_table_unref (hash);
  return ret;
}


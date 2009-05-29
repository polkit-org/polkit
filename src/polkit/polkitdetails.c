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
 * @short_description: Details
 *
 * An object used for passing details around.
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

PolkitDetails *
polkit_details_new (void)
{
  PolkitDetails *details;

  details = POLKIT_DETAILS (g_object_new (POLKIT_TYPE_DETAILS, NULL));

  return details;
}

PolkitDetails *
polkit_details_new_for_hash (GHashTable *hash)
{
  PolkitDetails *details;

  details = POLKIT_DETAILS (g_object_new (POLKIT_TYPE_DETAILS, NULL));
  if (hash != NULL)
    details->hash = g_hash_table_ref (hash);

  return details;
}

GHashTable *
polkit_details_get_hash (PolkitDetails *details)
{
  return details->hash;
}

const gchar *
polkit_details_lookup (PolkitDetails *details,
                       const gchar   *key)
{
  if (details->hash == NULL)
    return NULL;
  else
    return g_hash_table_lookup (details->hash, key);
}

void
polkit_details_insert (PolkitDetails *details,
                       const gchar   *key,
                       const gchar   *value)
{
  if (details->hash == NULL)
    details->hash = g_hash_table_new_full (g_str_hash,
                                           g_str_equal,
                                           g_free,
                                           g_free);
  g_hash_table_insert (details->hash, g_strdup (key), g_strdup (value));
}

gchar **
polkit_details_get_keys (PolkitDetails *details)
{
  GList *keys, *l;
  gchar **ret;
  guint n;

  if (details->hash == NULL)
    return NULL;

  keys = g_hash_table_get_keys (details->hash);
  ret = g_new0 (gchar*, g_list_length (keys) + 1);
  for (l = keys, n = 0; l != NULL; l = l->next, n++)
    ret[n] = g_strdup (l->data);

  g_list_free (keys);

  return ret;
}

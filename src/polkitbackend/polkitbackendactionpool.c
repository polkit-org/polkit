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
#include "polkitbackendactionpool.h"

/* TODO: locking */

typedef struct
{
  GFile *directory;

} PolkitBackendActionPoolPrivate;

enum
{
  PROP_0,
  PROP_DIRECTORY,
};

#define POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_BACKEND_ACTION_POOL, PolkitBackendActionPoolPrivate))

G_DEFINE_TYPE (PolkitBackendActionPool, polkit_backend_action_pool, G_TYPE_OBJECT);

static void
polkit_backend_action_pool_init (PolkitBackendActionPool *pool)
{
  PolkitBackendActionPoolPrivate *priv;

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);
}

static void
polkit_backend_action_pool_finalize (GObject *object)
{
  PolkitBackendActionPool *pool;
  PolkitBackendActionPoolPrivate *priv;

  pool = POLKIT_BACKEND_ACTION_POOL (object);
  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  if (priv->directory != NULL)
    g_object_unref (priv->directory);

  G_OBJECT_CLASS (polkit_backend_action_pool_parent_class)->finalize (object);
}

static void
polkit_backend_action_pool_get_property (GObject     *object,
                                         guint        prop_id,
                                         GValue      *value,
                                         GParamSpec  *pspec)
{
  PolkitBackendActionPool *pool;
  PolkitBackendActionPoolPrivate *priv;

  pool = POLKIT_BACKEND_ACTION_POOL (object);
  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      g_value_set_object (value, priv->directory);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_backend_action_pool_set_property (GObject       *object,
                                         guint          prop_id,
                                         const GValue  *value,
                                         GParamSpec    *pspec)
{
  PolkitBackendActionPool *pool;
  PolkitBackendActionPoolPrivate *priv;

  pool = POLKIT_BACKEND_ACTION_POOL (object);
  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      priv->directory = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_backend_action_pool_class_init (PolkitBackendActionPoolClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_backend_action_pool_get_property;
  gobject_class->set_property = polkit_backend_action_pool_set_property;
  gobject_class->finalize     = polkit_backend_action_pool_finalize;

  g_type_class_add_private (klass, sizeof (PolkitBackendActionPoolPrivate));

  /**
   * PolkitBackendActionPool:directory:
   *
   * The directory to load action description files from.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_DIRECTORY,
                                   g_param_spec_object ("directory",
                                                        "Directory",
                                                        "Directory to load action description files from",
                                                        G_TYPE_FILE,
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));
}

/**
 * polkit_backend_action_pool_new:
 * @directory: A #GFile for the directory holding PolicyKit action description files.
 *
 * Creates a new #PolkitBackendPool that can be used for looking up #PolkitActionDescription objects.
 *
 * Returns: A #PolkitBackendActionPool. Free with g_object_unref().
 **/
PolkitBackendActionPool *
polkit_backend_action_pool_new (GFile *directory)
{
  PolkitBackendActionPool *pool;

  pool = POLKIT_BACKEND_ACTION_POOL (g_object_new (POLKIT_TYPE_BACKEND_ACTION_POOL,
                                                   "directory", directory,
                                                   NULL));

  return pool;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_backend_action_pool_get_localized_actions:
 * @pool: A #PolkitBackendActionPool.
 * @locale: The locale to get descriptions for or %NULL for system locale.
 *
 * Gets all registered PolicyKit action descriptions from @pool with strings for @locale.
 *
 * Returns: A #GList of #PolkitActionDescription objects. This list
 *          should be freed with g_list_free() after each element have
 *          been unreffed with g_object_unref().
 **/
GList *
polkit_backend_action_pool_get_localized_actions (PolkitBackendActionPool *pool,
                                                  const gchar             *locale)
{
  GList *ret;
  PolkitBackendActionPoolPrivate *priv;

  g_return_val_if_fail (POLKIT_BACKEND_IS_ACTION_POOL (pool), NULL);

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  ret = NULL;

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

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

#include <polkit/polkit.h>
#include "polkitbackendconfigsource.h"

/**
 * SECTION:polkitbackendconfigsource
 * @title: PolkitBackendConfigSource
 * @short_description: Access configuration files
 *
 * The #PolkitBackendConfigSource class is a utility class to read
 * configuration data from a set of prioritized key-value files in a
 * given directory.
 */

struct _PolkitBackendConfigSourcePrivate
{
  GFile *directory;

  GFileMonitor *directory_monitor;

  /* sorted according to priority, higher priority is first */
  GList *key_files;

  gboolean has_data;
};

enum
{
  PROP_0,
  PROP_DIRECTORY,
};

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

static void polkit_backend_config_source_purge (PolkitBackendConfigSource *source);

static void polkit_backend_config_source_ensure (PolkitBackendConfigSource *source);

G_DEFINE_TYPE (PolkitBackendConfigSource, polkit_backend_config_source, G_TYPE_OBJECT);

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_config_source_init (PolkitBackendConfigSource *source)
{
  source->priv = G_TYPE_INSTANCE_GET_PRIVATE (source,
                                              POLKIT_BACKEND_TYPE_CONFIG_SOURCE,
                                              PolkitBackendConfigSourcePrivate);
}

static void
polkit_backend_config_source_finalize (GObject *object)
{
  PolkitBackendConfigSource *source = POLKIT_BACKEND_CONFIG_SOURCE (object);

  if (source->priv->directory != NULL)
    g_object_unref (source->priv->directory);

  if (source->priv->directory_monitor != NULL)
    g_object_unref (source->priv->directory_monitor);

  g_list_foreach (source->priv->key_files, (GFunc) g_key_file_free, NULL);
  g_list_free (source->priv->key_files);

  if (G_OBJECT_CLASS (polkit_backend_config_source_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_backend_config_source_parent_class)->finalize (object);
}


static void
polkit_backend_config_source_get_property (GObject    *object,
                                           guint       prop_id,
                                           GValue     *value,
                                           GParamSpec *pspec)
{
  PolkitBackendConfigSource *source = POLKIT_BACKEND_CONFIG_SOURCE (object);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      g_value_set_object (value, source->priv->directory);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_backend_config_source_set_property (GObject      *object,
                                           guint         prop_id,
                                           const GValue *value,
                                           GParamSpec   *pspec)
{
  PolkitBackendConfigSource *source = POLKIT_BACKEND_CONFIG_SOURCE (object);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      source->priv->directory = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
directory_monitor_changed (GFileMonitor     *monitor,
                           GFile            *file,
                           GFile            *other_file,
                           GFileMonitorEvent event_type,
                           gpointer          user_data)
{
  PolkitBackendConfigSource *source;

  source = POLKIT_BACKEND_CONFIG_SOURCE (user_data);

  if (file != NULL)
    {
      gchar *name;

      name = g_file_get_basename (file);

      //g_debug ("event_type=%d file=%p name=%s", event_type, file, name);

      if (!g_str_has_prefix (name, ".") &&
          !g_str_has_prefix (name, "#") &&
          g_str_has_suffix (name, ".conf") &&
          (event_type == G_FILE_MONITOR_EVENT_CREATED ||
           event_type == G_FILE_MONITOR_EVENT_DELETED ||
           event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT))
        {

          //g_debug ("match");

          /* now throw away all caches */
          polkit_backend_config_source_purge (source);
          g_signal_emit_by_name (source, "changed");
        }

      g_free (name);
    }
}

static void
polkit_backend_config_source_constructed (GObject *object)
{
  PolkitBackendConfigSource *source = POLKIT_BACKEND_CONFIG_SOURCE (object);
  GError *error;

  error = NULL;
  source->priv->directory_monitor = g_file_monitor_directory (source->priv->directory,
                                                              G_FILE_MONITOR_NONE,
                                                              NULL,
                                                              &error);
  if (source->priv->directory_monitor == NULL)
    {
      gchar *dir_name;
      dir_name = g_file_get_uri (source->priv->directory);
      g_warning ("Error monitoring directory %s: %s", dir_name, error->message);
      g_free (dir_name);
      g_error_free (error);
    }
  else
    {
      g_signal_connect (source->priv->directory_monitor,
                        "changed",
                        (GCallback) directory_monitor_changed,
                        source);
    }

  if (G_OBJECT_CLASS (polkit_backend_config_source_parent_class)->constructed != NULL)
    G_OBJECT_CLASS (polkit_backend_config_source_parent_class)->constructed (object);
}

static void
polkit_backend_config_source_class_init (PolkitBackendConfigSourceClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_backend_config_source_get_property;
  gobject_class->set_property = polkit_backend_config_source_set_property;
  gobject_class->finalize     = polkit_backend_config_source_constructed;
  gobject_class->finalize     = polkit_backend_config_source_finalize;

  g_type_class_add_private (klass, sizeof (PolkitBackendConfigSourcePrivate));

  /**
   * PolkitBackendConfigSource:directory:
   *
   * The directory to watch for configuration files.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_DIRECTORY,
                                   g_param_spec_object ("directory",
                                                        "Directory",
                                                        "The directory to watch for configuration files",
                                                        G_TYPE_FILE,
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

  /**
   * PolkitBackendConfiguSource::changed:
   * @source: A #PolkitBackendConfigSource.
   *
   * Emitted when configuration files in #PolkitBackendConfiguSource:directory changes.
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_BACKEND_TYPE_CONFIG_SOURCE,
                                          G_SIGNAL_RUN_LAST,
                                          G_STRUCT_OFFSET (PolkitBackendConfigSourceClass, changed),
                                          NULL,
                                          NULL,
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

/**
 * polkit_backend_config_source_new:
 * @directory: The directory to watch.
 *
 * Creates a new #PolkitBackendConfigSource object that reads
 * configuration from @directory. To watch for configuration changes,
 * connect to the #PolkitBackendConfigSource::changed signal.
 *
 * Returns: A #PolkitBackendConfigSource for @directory. Free with
 * g_object_unref().
 **/
PolkitBackendConfigSource *
polkit_backend_config_source_new (GFile *directory)
{
  PolkitBackendConfigSource *source;

  source = POLKIT_BACKEND_CONFIG_SOURCE (g_object_new (POLKIT_BACKEND_TYPE_CONFIG_SOURCE,
                                                       "directory", directory,
                                                       NULL));

  return source;
}

static void
polkit_backend_config_source_purge (PolkitBackendConfigSource *source)
{
  g_list_foreach (source->priv->key_files, (GFunc) g_key_file_free, NULL);
  g_list_free (source->priv->key_files);
  source->priv->key_files = NULL;

  source->priv->has_data = FALSE;
}

static gint
compare_filename (GFile *a, GFile *b)
{
  gchar *a_uri;
  gchar *b_uri;
  gint ret;

  a_uri = g_file_get_uri (a);
  b_uri = g_file_get_uri (b);

  /* TODO: use ASCII sort function? */
  ret = -g_strcmp0 (a_uri, b_uri);

  return ret;
}

static void
polkit_backend_config_source_ensure (PolkitBackendConfigSource *source)
{
  GFileEnumerator *enumerator;
  GFileInfo *file_info;
  GError *error;
  GList *files;
  GList *l;

  files = NULL;

  if (source->priv->has_data)
    goto out;

  polkit_backend_config_source_purge (source);

  error = NULL;
  enumerator = g_file_enumerate_children (source->priv->directory,
                                          "standard::*",
                                          G_FILE_QUERY_INFO_NONE,
                                          NULL,
                                          &error);
  if (enumerator == NULL)
    {
      gchar *dir_name;
      dir_name = g_file_get_uri (source->priv->directory);
      g_warning ("Error enumerating files in %s: %s", dir_name, error->message);
      g_free (dir_name);
      g_error_free (error);
      goto out;
    }

  while ((file_info = g_file_enumerator_next_file (enumerator, NULL, &error)) != NULL)
    {
      const gchar *name;

      name = g_file_info_get_name (file_info);

      /* only consider files ending in .conf */
      if (g_str_has_suffix (name, ".conf"))
        files = g_list_prepend (files, g_file_get_child (source->priv->directory, name));

      g_object_unref (file_info);
    }
  g_object_unref (enumerator);
  if (error != NULL)
    {
      g_warning ("Error enumerating files: %s", error->message);
      g_error_free (error);
      goto out;
    }

  files = g_list_sort (files, (GCompareFunc) compare_filename);

  /* process files; highest priority comes first */
  for (l = files; l != NULL; l = l->next)
    {
      GFile *file = G_FILE (l->data);
      gchar *filename;
      GKeyFile *key_file;

      filename = g_file_get_path (file);

      key_file = g_key_file_new ();

      error = NULL;
      if (!g_key_file_load_from_file (key_file,
                                      filename,
                                      G_KEY_FILE_NONE,
                                      NULL))
        {
          g_warning ("Error loading key-file %s: %s", filename, error->message);
          g_error_free (error);
          error = NULL;
          g_key_file_free (key_file);
        }
      else
        {
          source->priv->key_files = g_list_prepend (source->priv->key_files, key_file);
        }

      g_free (filename);
    }

  source->priv->key_files = g_list_reverse (source->priv->key_files);

 out:
  g_list_foreach (files, (GFunc) g_object_unref, NULL);
  g_list_free (files);
}

static GKeyFile *
find_key_file (PolkitBackendConfigSource  *source,
               const gchar                *group,
               const gchar                *key,
               GError                    **error)
{
  GList *l;
  GKeyFile *ret;

  ret = NULL;

  for (l = source->priv->key_files; l != NULL; l = l->next)
    {
      GKeyFile *key_file = l->data;

      if (g_key_file_has_key (key_file, group, key, NULL))
        {
          ret = key_file;
          goto out;
        }
    }

 out:
  if (ret == NULL)
    g_set_error_literal (error,
                         G_KEY_FILE_ERROR,
                         G_KEY_FILE_ERROR_NOT_FOUND,
                         "Group/Key combo not found in any config file");
  return ret;
}

/**
 * polkit_backend_config_source_get_integer:
 * @source: A PolkitBackendConfigSource.
 * @group: A group name.
 * @key: A key name.
 * @error: Return location for error or %NULL.
 *
 * Gets the value associated with @key under @group_name.
 *
 * Returns: The value or 0 if @error is set.
 **/
gint
polkit_backend_config_source_get_integer (PolkitBackendConfigSource  *source,
                                          const gchar                *group,
                                          const gchar                *key,
                                          GError                    **error)
{
  GKeyFile *key_file;

  polkit_backend_config_source_ensure (source);

  key_file = find_key_file (source, group, key, error);
  if (key_file == NULL)
    return 0;

  return g_key_file_get_integer (key_file, group, key, error);
}

/**
 * polkit_backend_config_source_get_boolean:
 * @source: A PolkitBackendConfigSource.
 * @group: A group name.
 * @key: A key name.
 * @error: Return location for error or %NULL.
 *
 * Gets the value associated with @key under @group_name.
 *
 * Returns: The value or %FALSE if @error is set.
 **/
gboolean
polkit_backend_config_source_get_boolean (PolkitBackendConfigSource  *source,
                                          const gchar                *group,
                                          const gchar                *key,
                                          GError                    **error)
{
  GKeyFile *key_file;

  polkit_backend_config_source_ensure (source);

  key_file = find_key_file (source, group, key, error);
  if (key_file == NULL)
    return FALSE;

  return g_key_file_get_boolean (key_file, group, key, error);
}

/**
 * polkit_backend_config_source_get_double:
 * @source: A PolkitBackendConfigSource.
 * @group: A group name.
 * @key: A key name.
 * @error: Return location for error or %NULL.
 *
 * Gets the value associated with @key under @group_name.
 *
 * Returns: The value or 0.0 if @error is set.
 **/
gdouble
polkit_backend_config_source_get_double (PolkitBackendConfigSource  *source,
                                         const gchar                *group,
                                         const gchar                *key,
                                         GError                    **error)
{
  GKeyFile *key_file;

  polkit_backend_config_source_ensure (source);

  key_file = find_key_file (source, group, key, error);
  if (key_file == NULL)
    return 0.0;

  return g_key_file_get_double (key_file, group, key, error);
}

/**
 * polkit_backend_config_source_get_string:
 * @source: A PolkitBackendConfigSource.
 * @group: A group name.
 * @key: A key name.
 * @error: Return location for error or %NULL.
 *
 * Gets the value associated with @key under @group_name.
 *
 * Returns: The value or %NULL if @error is set.
 **/
gchar *
polkit_backend_config_source_get_string (PolkitBackendConfigSource  *source,
                                         const gchar                *group,
                                         const gchar                *key,
                                         GError                    **error)
{
  GKeyFile *key_file;

  polkit_backend_config_source_ensure (source);

  key_file = find_key_file (source, group, key, error);
  if (key_file == NULL)
    return NULL;

  return g_key_file_get_string (key_file, group, key, error);
}

/**
 * polkit_backend_config_source_get_string_list:
 * @source: A PolkitBackendConfigSource.
 * @group: A group name.
 * @key: A key name.
 * @error: Return location for error or %NULL.
 *
 * Gets the values associated with @key under @group_name.
 *
 * Returns: The value or %NULL if @error is set.
 **/
gchar **
polkit_backend_config_source_get_string_list (PolkitBackendConfigSource  *source,
                                              const gchar                *group,
                                              const gchar                *key,
                                              GError                    **error)
{
  GKeyFile *key_file;

  polkit_backend_config_source_ensure (source);

  key_file = find_key_file (source, group, key, error);
  if (key_file == NULL)
    return NULL;

  return g_key_file_get_string_list (key_file, group, key, NULL, error);
}

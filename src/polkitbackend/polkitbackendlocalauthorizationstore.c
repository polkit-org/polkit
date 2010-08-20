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

#include <string.h>
#include <polkit/polkit.h>
#include "polkitbackendlocalauthorizationstore.h"

/* <internal>
 * SECTION:polkitbackendlocalauthorizationstore
 * @title: PolkitBackendLocalAuthorizationStore
 * @short_description: Watches a directory for authorization files
 *
 * #PolkitBackendLocalAuthorizationStore is a utility class to watch
 * and read authorization files from a directory.
 */

struct _PolkitBackendLocalAuthorizationStorePrivate
{
  GFile *directory;
  gchar *extension;

  GFileMonitor *directory_monitor;

  /* List of LocalAuthorization objects */
  GList *authorizations;

  gboolean has_data;
};

enum
{
  PROP_0,
  PROP_DIRECTORY,
  PROP_EXTENSION,
};

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

static void polkit_backend_local_authorization_store_purge (PolkitBackendLocalAuthorizationStore *store);

static void polkit_backend_local_authorization_store_ensure (PolkitBackendLocalAuthorizationStore *store);

G_DEFINE_TYPE (PolkitBackendLocalAuthorizationStore, polkit_backend_local_authorization_store, G_TYPE_OBJECT);

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  gchar *id;

  GList *identity_specs;
  GList *action_specs;

  PolkitImplicitAuthorization result_any;
  PolkitImplicitAuthorization result_inactive;
  PolkitImplicitAuthorization result_active;

  GHashTable *return_value;
} LocalAuthorization;

static void
local_authorization_free (LocalAuthorization *authorization)
{
  g_free (authorization->id);
  g_list_foreach (authorization->identity_specs, (GFunc) g_pattern_spec_free, NULL);
  g_list_free (authorization->identity_specs);
  g_list_foreach (authorization->action_specs, (GFunc) g_pattern_spec_free, NULL);
  g_list_free (authorization->action_specs);
  if (authorization->return_value != NULL)
    g_hash_table_unref (authorization->return_value);
  g_free (authorization);
}


static LocalAuthorization *
local_authorization_new (GKeyFile      *key_file,
                         const gchar   *filename,
                         const gchar   *group,
                         GError       **error)
{
  LocalAuthorization *authorization;
  gchar **identity_strings;
  gchar **action_strings;
  gchar *result_any_string;
  gchar *result_inactive_string;
  gchar *result_active_string;
  gchar **return_value_strings;
  guint n;

  identity_strings = NULL;
  action_strings = NULL;
  result_any_string = NULL;
  result_inactive_string = NULL;
  result_active_string = NULL;
  return_value_strings = NULL;

  authorization = g_new0 (LocalAuthorization, 1);

  identity_strings = g_key_file_get_string_list (key_file,
                                                 group,
                                                 "Identity",
                                                 NULL,
                                                 error);
  if (identity_strings == NULL)
    {
      local_authorization_free (authorization);
      authorization = NULL;
      goto out;
    }
  for (n = 0; identity_strings[n] != NULL; n++)
    {
      authorization->identity_specs = g_list_prepend (authorization->identity_specs,
                                                      g_pattern_spec_new (identity_strings[n]));
    }

  action_strings = g_key_file_get_string_list (key_file,
                                                 group,
                                                 "Action",
                                                 NULL,
                                                 error);
  if (action_strings == NULL)
    {
      local_authorization_free (authorization);
      authorization = NULL;
      goto out;
    }
  for (n = 0; action_strings[n] != NULL; n++)
    {
      authorization->action_specs = g_list_prepend (authorization->action_specs,
                                                    g_pattern_spec_new (action_strings[n]));
    }

  authorization->result_any = POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN;
  authorization->result_inactive = POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN;
  authorization->result_active = POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN;

  result_any_string = g_key_file_get_string (key_file,
                                             group,
                                             "ResultAny",
                                             NULL);
  if (result_any_string != NULL)
    {
      if (!polkit_implicit_authorization_from_string (result_any_string,
                                                      &authorization->result_any))
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot parse ResultAny string `%s'", result_any_string);
          local_authorization_free (authorization);
          authorization = NULL;
          goto out;
        }
    }

  result_inactive_string = g_key_file_get_string (key_file,
                                                  group,
                                                  "ResultInactive",
                                                  NULL);
  if (result_inactive_string != NULL)
    {
      if (!polkit_implicit_authorization_from_string (result_inactive_string,
                                                      &authorization->result_inactive))
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot parse ResultInactive string `%s'", result_inactive_string);
          local_authorization_free (authorization);
          authorization = NULL;
          goto out;
        }
    }

  result_active_string = g_key_file_get_string (key_file,
                                                group,
                                                "ResultActive",
                                                NULL);
  if (result_active_string != NULL)
    {
      if (!polkit_implicit_authorization_from_string (result_active_string,
                                                      &authorization->result_active))
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Cannot parse ResultActive string `%s'", result_active_string);
          local_authorization_free (authorization);
          authorization = NULL;
          goto out;
        }
    }

  if (result_any_string == NULL && result_inactive_string == NULL && result_active_string == NULL)
    {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Must have at least one of ResultAny, ResultInactive and ResultActive");
          local_authorization_free (authorization);
          authorization = NULL;
          goto out;
    }

  return_value_strings = g_key_file_get_string_list (key_file,
                                                     group,
                                                     "ReturnValue",
                                                     NULL,
                                                     error);
  if (return_value_strings != NULL)
    {
      for (n = 0; return_value_strings[n] != NULL; n++)
        {
          gchar *p;
          const gchar *key;
          const gchar *value;

          p = strchr (return_value_strings[n], '=');
          if (p == NULL)
            {
              g_warning ("Item `%s' in ReturnValue is malformed. Ignoring.",
                         return_value_strings[n]);
              continue;
            }

          *p = '\0';
          key = return_value_strings[n];
          value = p + 1;

          if (authorization->return_value == NULL)
            {
              authorization->return_value = g_hash_table_new_full (g_str_hash,
                                                                   g_str_equal,
                                                                   g_free,
                                                                   g_free);
            }
          g_hash_table_insert (authorization->return_value, g_strdup (key), g_strdup (value));
        }
    }

  authorization->id = g_strdup_printf ("%s::%s", filename, group);

 out:
  g_strfreev (identity_strings);
  g_free (action_strings);
  g_free (result_any_string);
  g_free (result_inactive_string);
  g_free (result_active_string);
  g_strfreev (return_value_strings);
  return authorization;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
polkit_backend_local_authorization_store_init (PolkitBackendLocalAuthorizationStore *store)
{
  store->priv = G_TYPE_INSTANCE_GET_PRIVATE (store,
                                             POLKIT_BACKEND_TYPE_LOCAL_AUTHORIZATION_STORE,
                                             PolkitBackendLocalAuthorizationStorePrivate);
}

static void
polkit_backend_local_authorization_store_finalize (GObject *object)
{
  PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (object);

  if (store->priv->directory != NULL)
    g_object_unref (store->priv->directory);
  g_free (store->priv->extension);

  if (store->priv->directory_monitor != NULL)
    g_object_unref (store->priv->directory_monitor);

  g_list_foreach (store->priv->authorizations, (GFunc) local_authorization_free, NULL);
  g_list_free (store->priv->authorizations);

  if (G_OBJECT_CLASS (polkit_backend_local_authorization_store_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_backend_local_authorization_store_parent_class)->finalize (object);
}


static void
polkit_backend_local_authorization_store_get_property (GObject    *object,
                                                       guint       prop_id,
                                                       GValue     *value,
                                                       GParamSpec *pspec)
{
  PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (object);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      g_value_set_object (value, store->priv->directory);
      break;

    case PROP_EXTENSION:
      g_value_set_string (value, store->priv->extension);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_backend_local_authorization_store_set_property (GObject      *object,
                                                       guint         prop_id,
                                                       const GValue *value,
                                                       GParamSpec   *pspec)
{
  PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (object);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      store->priv->directory = g_value_dup_object (value);
      break;

    case PROP_EXTENSION:
      store->priv->extension = g_value_dup_string (value);
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
  PolkitBackendLocalAuthorizationStore *store;

  store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (user_data);

  if (file != NULL)
    {
      gchar *name;

      name = g_file_get_basename (file);

      //g_debug ("event_type=%d file=%p name=%s", event_type, file, name);

      if (!g_str_has_prefix (name, ".") &&
          !g_str_has_prefix (name, "#") &&
          g_str_has_suffix (name, store->priv->extension) &&
          (event_type == G_FILE_MONITOR_EVENT_CREATED ||
           event_type == G_FILE_MONITOR_EVENT_DELETED ||
           event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT))
        {

          //g_debug ("match");

          /* now throw away all caches */
          polkit_backend_local_authorization_store_purge (store);
          g_signal_emit_by_name (store, "changed");
        }

      g_free (name);
    }
}

static void
polkit_backend_local_authorization_store_constructed (GObject *object)
{
  PolkitBackendLocalAuthorizationStore *store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (object);
  GError *error;

  error = NULL;
  store->priv->directory_monitor = g_file_monitor_directory (store->priv->directory,
                                                              G_FILE_MONITOR_NONE,
                                                              NULL,
                                                              &error);
  if (store->priv->directory_monitor == NULL)
    {
      gchar *dir_name;
      dir_name = g_file_get_uri (store->priv->directory);
      g_warning ("Error monitoring directory %s: %s", dir_name, error->message);
      g_free (dir_name);
      g_error_free (error);
    }
  else
    {
      g_signal_connect (store->priv->directory_monitor,
                        "changed",
                        (GCallback) directory_monitor_changed,
                        store);
    }

  if (G_OBJECT_CLASS (polkit_backend_local_authorization_store_parent_class)->constructed != NULL)
    G_OBJECT_CLASS (polkit_backend_local_authorization_store_parent_class)->constructed (object);
}

static void
polkit_backend_local_authorization_store_class_init (PolkitBackendLocalAuthorizationStoreClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_backend_local_authorization_store_get_property;
  gobject_class->set_property = polkit_backend_local_authorization_store_set_property;
  gobject_class->constructed  = polkit_backend_local_authorization_store_constructed;
  gobject_class->finalize     = polkit_backend_local_authorization_store_finalize;

  g_type_class_add_private (klass, sizeof (PolkitBackendLocalAuthorizationStorePrivate));

  /**
   * PolkitBackendLocalAuthorizationStore:directory:
   *
   * The directory to watch for authorization files.
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
   * PolkitBackendLocalAuthorizationStore:extension:
   *
   * The file extension for files to consider, e.g. <quote>.pkla</quote>.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_EXTENSION,
                                   g_param_spec_string ("extension",
                                                        "Extension",
                                                        "The extension of files to consider",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT_ONLY |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

  /**
   * PolkitBackendConfiguStore::changed:
   * @store: A #PolkitBackendLocalAuthorizationStore.
   *
   * Emitted when configuration files in #PolkitBackendConfiguStore:directory changes.
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_BACKEND_TYPE_LOCAL_AUTHORIZATION_STORE,
                                          G_SIGNAL_RUN_LAST,
                                          G_STRUCT_OFFSET (PolkitBackendLocalAuthorizationStoreClass, changed),
                                          NULL,
                                          NULL,
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

/**
 * polkit_backend_local_authorization_store_new:
 * @directory: The directory to watch.
 * @extension: The extension of files to consider e.g. <quote>.pkla</quote>.
 *
 * Creates a new #PolkitBackendLocalAuthorizationStore object that
 * reads authorizations from @directory with file extension
 * @extension. To watch for configuration changes, connect to the
 * #PolkitBackendLocalAuthorizationStore::changed signal.
 *
 * Returns: A #PolkitBackendLocalAuthorizationStore. Free with
 * g_object_unref().
 **/
PolkitBackendLocalAuthorizationStore *
polkit_backend_local_authorization_store_new (GFile       *directory,
                                              const gchar *extension)
{
  PolkitBackendLocalAuthorizationStore *store;

  store = POLKIT_BACKEND_LOCAL_AUTHORIZATION_STORE (g_object_new (POLKIT_BACKEND_TYPE_LOCAL_AUTHORIZATION_STORE,
                                                                  "directory", directory,
                                                                  "extension", extension,
                                                                  NULL));

  return store;
}

static void
polkit_backend_local_authorization_store_purge (PolkitBackendLocalAuthorizationStore *store)
{
  gchar *path;

  path = g_file_get_path (store->priv->directory);
  g_debug ("Dropping all .pkla caches for directory `%s'", path);
  g_free (path);

  g_list_foreach (store->priv->authorizations, (GFunc) local_authorization_free, NULL);
  g_list_free (store->priv->authorizations);
  store->priv->authorizations = NULL;

  store->priv->has_data = FALSE;
}

static void
polkit_backend_local_authorization_store_ensure (PolkitBackendLocalAuthorizationStore *store)
{
  GFileEnumerator *enumerator;
  GFileInfo *file_info;
  GError *error;
  GList *files;
  GList *l;

  files = NULL;

  if (store->priv->has_data)
    goto out;

  polkit_backend_local_authorization_store_purge (store);

  error = NULL;
  enumerator = g_file_enumerate_children (store->priv->directory,
                                          "standard::*",
                                          G_FILE_QUERY_INFO_NONE,
                                          NULL,
                                          &error);
  if (enumerator == NULL)
    {
      gchar *dir_name;
      dir_name = g_file_get_uri (store->priv->directory);
      g_warning ("Error enumerating files in %s: %s", dir_name, error->message);
      g_free (dir_name);
      g_error_free (error);
      goto out;
    }

  while ((file_info = g_file_enumerator_next_file (enumerator, NULL, &error)) != NULL)
    {
      const gchar *name;

      name = g_file_info_get_name (file_info);

      /* only consider files with the appropriate extension */
      if (g_str_has_suffix (name, store->priv->extension) && name[0] != '.')
        files = g_list_prepend (files, g_file_get_child (store->priv->directory, name));

      g_object_unref (file_info);
    }
  g_object_unref (enumerator);
  if (error != NULL)
    {
      g_warning ("Error enumerating files: %s", error->message);
      g_error_free (error);
      goto out;
    }

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
                                      &error))
        {
          g_warning ("Error loading key-file %s: %s", filename, error->message);
          g_error_free (error);
          error = NULL;
          g_key_file_free (key_file);
        }
      else
        {
          gchar **groups;
          guint n;

          groups = g_key_file_get_groups (key_file, NULL);
          for (n = 0; groups[n] != NULL; n++)
            {
              LocalAuthorization *authorization;

              error = NULL;
              authorization = local_authorization_new (key_file, filename, groups[n], &error);
              if (authorization == NULL)
                {
                  g_warning ("Error parsing group `%s' in file `%s': %s",
                             groups[n],
                             filename,
                             error->message);
                  g_error_free (error);
                }
              else
                {
                  store->priv->authorizations = g_list_prepend (store->priv->authorizations,
                                                                authorization);
                }
            }
          g_strfreev (groups);

          store->priv->authorizations = g_list_reverse (store->priv->authorizations);

          g_key_file_free (key_file);
        }

      g_free (filename);
    }

  store->priv->has_data = TRUE;

 out:
  g_list_foreach (files, (GFunc) g_object_unref, NULL);
  g_list_free (files);
}

/**
 * polkit_backend_local_authorization_store_lookup:
 * @store: A #PolkitBackendLocalAuthorizationStore.
 * @identity: The identity to check for.
 * @action_id: The action id to check for.
 * @details: Details for @action.
 * @out_result_any: Return location for the result for any subjects if the look up matched.
 * @out_result_inactive: Return location for the result for subjects in local inactive sessions if the look up matched.
 * @out_result_active: Return location for the result for subjects in local active sessions if the look up matched.
 * @out_details: %NULL or a #PolkitDetails object to append key/value pairs to on a positive match.
 *
 * Checks if an authorization entry from @store matches @identity, @action_id and @details.
 *
 * Returns: %TRUE if @store has an authorization entry that matches
 *     @identity, @action_id and @details. Otherwise %FALSE.
 */
gboolean
polkit_backend_local_authorization_store_lookup (PolkitBackendLocalAuthorizationStore *store,
                                                 PolkitIdentity                       *identity,
                                                 const gchar                          *action_id,
                                                 PolkitDetails                        *details,
                                                 PolkitImplicitAuthorization          *out_result_any,
                                                 PolkitImplicitAuthorization          *out_result_inactive,
                                                 PolkitImplicitAuthorization          *out_result_active,
                                                 PolkitDetails                        *out_details)
{
  GList *l, *ll;
  gboolean ret;
  gchar *identity_string;

  g_return_val_if_fail (POLKIT_BACKEND_IS_LOCAL_AUTHORIZATION_STORE (store), FALSE);
  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), FALSE);
  g_return_val_if_fail (action_id != NULL, FALSE);
  g_return_val_if_fail (POLKIT_IS_DETAILS (details), FALSE);
  g_return_val_if_fail (out_result_any != NULL, FALSE);
  g_return_val_if_fail (out_result_inactive != NULL, FALSE);
  g_return_val_if_fail (out_result_active != NULL, FALSE);

  ret = FALSE;
  identity_string = NULL;

  polkit_backend_local_authorization_store_ensure (store);

  for (l = store->priv->authorizations; l != NULL; l = l->next)
    {
      LocalAuthorization *authorization = l->data;

      /* first match the action */
      for (ll = authorization->action_specs; ll != NULL; ll = ll->next)
        {
          if (g_pattern_match_string ((GPatternSpec *) ll->data, action_id))
            break;
        }
      if (ll == NULL)
        continue;

      /* then match the identity */
      if (identity_string == NULL)
        identity_string = polkit_identity_to_string (identity);
      for (ll = authorization->identity_specs; ll != NULL; ll = ll->next)
        {
          if (g_pattern_match_string ((GPatternSpec *) ll->data, identity_string))
            break;
        }
      if (ll == NULL)
        continue;

      /* Yay, a match! However, keep going since subsequent authorization entries may modify the result */
      *out_result_any = authorization->result_any;
      *out_result_inactive = authorization->result_inactive;
      *out_result_active = authorization->result_active;
      ret = TRUE;

      if (out_details != NULL && authorization->return_value != NULL)
        {
          GHashTableIter iter;
          const gchar *key;
          const gchar *value;

          g_hash_table_iter_init (&iter, authorization->return_value);
          while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
            {
              polkit_details_insert (out_details, key, value);
            }
        }

#if 0
      g_debug ("authorization with id `%s' matched action_id `%s' for identity `%s'",
               authorization->id,
               action_id,
               polkit_identity_to_string (identity));
#endif
    }

  g_free (identity_string);

  return ret;
}

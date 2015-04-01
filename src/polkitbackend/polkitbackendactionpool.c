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
#include <expat.h>

#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>

#include "polkitbackendactionpool.h"

/* <internal>
 * SECTION:polkitbackendactionpool
 * @title: PolkitBackendActionPool
 * @short_description: Registered actions
 *
 * The #PolkitBackendActionPool class is a utility class to look up registered PolicyKit actions.
 */

typedef struct
{
  gchar *vendor_name;
  gchar *vendor_url;
  gchar *icon_name;
  gchar *description;
  gchar *message;

  PolkitImplicitAuthorization implicit_authorization_any;
  PolkitImplicitAuthorization implicit_authorization_inactive;
  PolkitImplicitAuthorization implicit_authorization_active;

  /* each of these map from the locale identifer (e.g. da_DK) to the localized value */
  GHashTable *localized_description;
  GHashTable *localized_message;

  /* this maps from annotation key (string) to annotation value (also a string) */
  GHashTable *annotations;
} ParsedAction;

static void
parsed_action_free (ParsedAction *action)
{
  g_free (action->vendor_name);
  g_free (action->vendor_url);
  g_free (action->icon_name);
  g_free (action->description);
  g_free (action->message);

  g_hash_table_unref (action->localized_description);
  g_hash_table_unref (action->localized_message);

  g_hash_table_unref (action->annotations);
  g_free (action);
}

static gboolean process_policy_file (PolkitBackendActionPool *pool,
                                     const gchar *xml,
                                     GError **error);

static void ensure_file (PolkitBackendActionPool *pool,
                         GFile *file);

static void ensure_all_files (PolkitBackendActionPool *pool);

static const gchar *_localize (GHashTable *translations,
                               const gchar *untranslated,
                               const gchar *lang);

typedef struct
{
  /* directory with .policy files, e.g. /usr/share/polkit-1/actions */
  GFile *directory;

  GFileMonitor *dir_monitor;

  /* maps from action_id to a ParsedAction struct */
  GHashTable *parsed_actions;

  /* maps from URI of parsed file to nothing */
  GHashTable *parsed_files;

  /* is TRUE only when we've read all files */
  gboolean has_loaded_all_files;

} PolkitBackendActionPoolPrivate;

enum
{
  PROP_0,
  PROP_DIRECTORY,
};

#define POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_ACTION_POOL, PolkitBackendActionPoolPrivate))

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = {0};

G_DEFINE_TYPE (PolkitBackendActionPool, polkit_backend_action_pool, G_TYPE_OBJECT);

static void
polkit_backend_action_pool_init (PolkitBackendActionPool *pool)
{
  PolkitBackendActionPoolPrivate *priv;

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  priv->parsed_actions = g_hash_table_new_full (g_str_hash,
                                                g_str_equal,
                                                g_free,
                                                (GDestroyNotify) parsed_action_free);

  priv->parsed_files = g_hash_table_new_full (g_str_hash,
                                              g_str_equal,
                                              g_free,
                                              NULL);
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

  if (priv->dir_monitor != NULL)
    g_object_unref (priv->dir_monitor);

  if (priv->parsed_actions != NULL)
    g_hash_table_unref (priv->parsed_actions);

  if (priv->parsed_files != NULL)
    g_hash_table_unref (priv->parsed_files);

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
dir_monitor_changed (GFileMonitor     *monitor,
                     GFile            *file,
                     GFile            *other_file,
                     GFileMonitorEvent event_type,
                     gpointer          user_data)
{
  PolkitBackendActionPool *pool;
  PolkitBackendActionPoolPrivate *priv;

  pool = POLKIT_BACKEND_ACTION_POOL (user_data);
  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  /* TODO: maybe rate-limit so storms of events are collapsed into one with a 500ms resolution?
   *       Because when editing a file with emacs we get 4-8 events..
   */

  if (file != NULL)
    {
      gchar *name;

      name = g_file_get_basename (file);

      //g_debug ("event_type=%d file=%p name=%s", event_type, file, name);

      if (!g_str_has_prefix (name, ".") &&
          !g_str_has_prefix (name, "#") &&
          g_str_has_suffix (name, ".policy") &&
          (event_type == G_FILE_MONITOR_EVENT_CREATED ||
           event_type == G_FILE_MONITOR_EVENT_DELETED ||
           event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT))
        {

          //g_debug ("match");

          /* now throw away all caches */
          g_hash_table_remove_all (priv->parsed_files);
          g_hash_table_remove_all (priv->parsed_actions);
          priv->has_loaded_all_files = FALSE;

          g_signal_emit_by_name (pool, "changed");
        }

      g_free (name);
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
  GError *error;

  pool = POLKIT_BACKEND_ACTION_POOL (object);
  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  switch (prop_id)
    {
    case PROP_DIRECTORY:
      priv->directory = g_value_dup_object (value);

      error = NULL;
      priv->dir_monitor = g_file_monitor_directory (priv->directory,
                                                    G_FILE_MONITOR_NONE,
                                                    NULL,
                                                    &error);
      if (priv->dir_monitor == NULL)
        {
          g_warning ("Error monitoring actions directory: %s", error->message);
          g_error_free (error);
        }
      else
        {
          g_signal_connect (priv->dir_monitor,
                            "changed",
                            (GCallback) dir_monitor_changed,
                            pool);
        }
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

  /**
   * PolkitBackendActionPool::changed:
   * @action_pool: A #PolkitBackendActionPool.
   *
   * Emitted when action files in the supplied directory changes.
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_BACKEND_TYPE_ACTION_POOL,
                                          G_SIGNAL_RUN_LAST,
                                          0,                      /* class offset     */
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
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

  pool = POLKIT_BACKEND_ACTION_POOL (g_object_new (POLKIT_BACKEND_TYPE_ACTION_POOL,
                                                   "directory", directory,
                                                   NULL));

  return pool;
}

/**
 * polkit_backend_action_pool_get_action:
 * @pool: A #PolkitBackendActionPool.
 * @action_id: A PolicyKit action identifier.
 * @locale: The locale to get descriptions for or %NULL for system locale.
 *
 * Gets a #PolkitActionDescription object describing the action with identifier @action_id.
 *
 * Returns: A #PolkitActionDescription (free with g_object_unref()) or %NULL
 *          if @action_id isn't registered or valid.
 **/
PolkitActionDescription *
polkit_backend_action_pool_get_action (PolkitBackendActionPool *pool,
                                       const gchar             *action_id,
                                       const gchar             *locale)
{
  PolkitBackendActionPoolPrivate *priv;
  PolkitActionDescription *ret;
  ParsedAction *parsed_action;
  const gchar *description;
  const gchar *message;

  g_return_val_if_fail (POLKIT_BACKEND_IS_ACTION_POOL (pool), NULL);

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  /* TODO: just compute the name of the expected file and ensure it's parsed */
  ensure_all_files (pool);

  ret = NULL;

  parsed_action = g_hash_table_lookup (priv->parsed_actions, action_id);
  if (parsed_action == NULL)
    {
      g_warning ("Unknown action_id '%s'", action_id);
      goto out;
    }

  description = _localize (parsed_action->localized_description,
                           parsed_action->description,
                           locale);
  message = _localize (parsed_action->localized_message,
                       parsed_action->message,
                       locale);

  ret = polkit_action_description_new (action_id,
                                       description,
                                       message,
                                       parsed_action->vendor_name,
                                       parsed_action->vendor_url,
                                       parsed_action->icon_name,
                                       parsed_action->implicit_authorization_any,
                                       parsed_action->implicit_authorization_inactive,
                                       parsed_action->implicit_authorization_active,
                                       parsed_action->annotations);

 out:
  return ret;
}

/**
 * polkit_backend_action_pool_get_all_actions:
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
polkit_backend_action_pool_get_all_actions (PolkitBackendActionPool *pool,
                                            const gchar             *locale)
{
  GList *ret;
  PolkitBackendActionPoolPrivate *priv;
  GHashTableIter hash_iter;
  const gchar *action_id;

  g_return_val_if_fail (POLKIT_BACKEND_IS_ACTION_POOL (pool), NULL);

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  ensure_all_files (pool);

  ret = NULL;

  g_hash_table_iter_init (&hash_iter, priv->parsed_actions);
  while (g_hash_table_iter_next (&hash_iter, (gpointer) &action_id, NULL))
    {
      PolkitActionDescription *action_desc;

      action_desc = polkit_backend_action_pool_get_action (pool,
                                                           action_id,
                                                           locale);

      if (action_desc != NULL)
        ret = g_list_prepend (ret, action_desc);
    }

  ret = g_list_reverse (ret);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
ensure_file (PolkitBackendActionPool *pool,
             GFile *file)
{
  PolkitBackendActionPoolPrivate *priv;
  gchar *contents;
  GError *error;
  gchar *uri;

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  uri = g_file_get_uri (file);

  if (g_hash_table_lookup (priv->parsed_files, uri) != NULL)
    goto out;

  error = NULL;
  if (!g_file_load_contents (file,
                             NULL,
                             &contents,
                             NULL,
                             NULL,
                             &error))
    {
      g_warning ("Error loading file with URI '%s': %s", uri, error->message);
      goto out;
    }

  if (!process_policy_file (pool,
                            contents,
                            &error))
    {
      g_warning ("Error parsing file with URI '%s': %s", uri, error->message);
      g_free (contents);
      goto out;
    }

  g_free (contents);

  /* steal uri */
  g_hash_table_insert (priv->parsed_files, uri, NULL);
  uri = NULL;

 out:
  g_free (uri);
}

static void
ensure_all_files (PolkitBackendActionPool *pool)
{
  PolkitBackendActionPoolPrivate *priv;
  GFileEnumerator *e;
  GFileInfo *file_info;
  GError *error;

  priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pool);

  e = NULL;

  if (priv->has_loaded_all_files)
    goto out;

  error = NULL;
  e = g_file_enumerate_children (priv->directory,
                                 "standard::name",
                                 G_FILE_QUERY_INFO_NONE,
                                 NULL,
                                 &error);
  if (error != NULL)
    {
      g_warning ("Error enumerating files: %s", error->message);
      goto out;
    }

  while ((file_info = g_file_enumerator_next_file (e, NULL, &error)) != NULL)
    {
      const gchar *name;

      name = g_file_info_get_name (file_info);
      /* only consider files with the right suffix */
      if (g_str_has_suffix (name, ".policy"))
        {
          GFile *file;

          file = g_file_get_child (priv->directory, name);

          ensure_file (pool, file);

          g_object_unref (file);
        }

      g_object_unref (file_info);

    } /* for all files */

  priv->has_loaded_all_files = TRUE;

 out:

  if (e != NULL)
    g_object_unref (e);
}

/* ---------------------------------------------------------------------------------------------------- */

enum {
  STATE_NONE,
  STATE_UNKNOWN_TAG,
  STATE_IN_POLICY_CONFIG,
  STATE_IN_POLICY_VENDOR,
  STATE_IN_POLICY_VENDOR_URL,
  STATE_IN_POLICY_ICON_NAME,
  STATE_IN_ACTION,
  STATE_IN_ACTION_DESCRIPTION,
  STATE_IN_ACTION_MESSAGE,
  STATE_IN_ACTION_VENDOR,
  STATE_IN_ACTION_VENDOR_URL,
  STATE_IN_ACTION_ICON_NAME,
  STATE_IN_DEFAULTS,
  STATE_IN_DEFAULTS_ALLOW_ANY,
  STATE_IN_DEFAULTS_ALLOW_INACTIVE,
  STATE_IN_DEFAULTS_ALLOW_ACTIVE,
  STATE_IN_ANNOTATE
};

#define PARSER_MAX_DEPTH 32

typedef struct {
  XML_Parser parser;
  int state;
  int state_stack[PARSER_MAX_DEPTH];
  int stack_depth;

  char *global_vendor;
  char *global_vendor_url;
  char *global_icon_name;

  char *action_id;
  char *vendor;
  char *vendor_url;
  char *icon_name;

  PolkitImplicitAuthorization implicit_authorization_any;
  PolkitImplicitAuthorization implicit_authorization_inactive;
  PolkitImplicitAuthorization implicit_authorization_active;

  GHashTable *policy_descriptions;
  GHashTable *policy_messages;

  char *policy_description_nolang;
  char *policy_message_nolang;

  /* the value of xml:lang for the thing we're reading in _cdata() */
  char *elem_lang;

  char *annotate_key;
  GHashTable *annotations;

  PolkitBackendActionPool *pool;
} ParserData;

static void
pd_unref_action_data (ParserData *pd)
{
  g_free (pd->action_id);
  pd->action_id = NULL;

  g_free (pd->vendor);
  pd->vendor = NULL;
  g_free (pd->vendor_url);
  pd->vendor_url = NULL;
  g_free (pd->icon_name);
  pd->icon_name = NULL;

  g_free (pd->policy_description_nolang);
  pd->policy_description_nolang = NULL;
  g_free (pd->policy_message_nolang);
  pd->policy_message_nolang = NULL;
  if (pd->policy_descriptions != NULL)
    {
      g_hash_table_unref (pd->policy_descriptions);
      pd->policy_descriptions = NULL;
    }
  if (pd->policy_messages != NULL)
    {
      g_hash_table_unref (pd->policy_messages);
      pd->policy_messages = NULL;
    }
  g_free (pd->annotate_key);
  pd->annotate_key = NULL;
  if (pd->annotations != NULL)
    {
      g_hash_table_unref (pd->annotations);
      pd->annotations = NULL;
    }
  g_free (pd->elem_lang);
  pd->elem_lang = NULL;
}

static void
pd_unref_data (ParserData *pd)
{
  pd_unref_action_data (pd);

  g_free (pd->global_vendor);
  pd->global_vendor = NULL;
  g_free (pd->global_vendor_url);
  pd->global_vendor_url = NULL;
  g_free (pd->global_icon_name);
  pd->global_icon_name = NULL;
}

static void
_start (void *data, const char *el, const char **attr)
{
  guint state;
  guint num_attr;
  ParserData *pd = data;

  for (num_attr = 0; attr[num_attr] != NULL; num_attr++)
    ;

  state = STATE_NONE;

  switch (pd->state)
    {
    case STATE_NONE:
      if (strcmp (el, "policyconfig") == 0)
        {
          state = STATE_IN_POLICY_CONFIG;
        }
      break;

    case STATE_IN_POLICY_CONFIG:
      if (strcmp (el, "action") == 0)
        {
          if (num_attr != 2 || strcmp (attr[0], "id") != 0)
            goto error;
          state = STATE_IN_ACTION;

          //if (!polkit_action_validate_id (attr[1]))
          //        goto error;

          pd_unref_action_data (pd);
          pd->action_id = g_strdup (attr[1]);
          pd->policy_descriptions = g_hash_table_new_full (g_str_hash,
                                                           g_str_equal,
                                                           g_free,
                                                           g_free);
          pd->policy_messages = g_hash_table_new_full (g_str_hash,
                                                       g_str_equal,
                                                       g_free,
                                                       g_free);
          pd->annotations = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
          /* initialize defaults */
          pd->implicit_authorization_any = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
          pd->implicit_authorization_inactive = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
          pd->implicit_authorization_active = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
        }
      else if (strcmp (el, "vendor") == 0 && num_attr == 0)
        {
          state = STATE_IN_POLICY_VENDOR;
        }
      else if (strcmp (el, "vendor_url") == 0 && num_attr == 0)
        {
          state = STATE_IN_POLICY_VENDOR_URL;
        }
      else if (strcmp (el, "icon_name") == 0 && num_attr == 0)
        {
          state = STATE_IN_POLICY_ICON_NAME;
        }
      break;

    case STATE_IN_ACTION:
      if (strcmp (el, "defaults") == 0)
        {
          state = STATE_IN_DEFAULTS;
        }
      else if (strcmp (el, "description") == 0)
        {
          if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0)
            {
              pd->elem_lang = g_strdup (attr[1]);
            }
          state = STATE_IN_ACTION_DESCRIPTION;
        }
      else if (strcmp (el, "message") == 0)
        {
          if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0)
            {
              pd->elem_lang = g_strdup (attr[1]);
            }
          state = STATE_IN_ACTION_MESSAGE;
        }
      else if (strcmp (el, "vendor") == 0 && num_attr == 0)
        {
          state = STATE_IN_ACTION_VENDOR;
        }
      else if (strcmp (el, "vendor_url") == 0 && num_attr == 0)
        {
          state = STATE_IN_ACTION_VENDOR_URL;
        }
      else if (strcmp (el, "icon_name") == 0 && num_attr == 0)
        {
          state = STATE_IN_ACTION_ICON_NAME;
        }
      else if (strcmp (el, "annotate") == 0)
        {
          if (num_attr != 2 || strcmp (attr[0], "key") != 0)
            goto error;

          state = STATE_IN_ANNOTATE;

          g_free (pd->annotate_key);
          pd->annotate_key = g_strdup (attr[1]);
        }
      break;

    case STATE_IN_DEFAULTS:
      if (strcmp (el, "allow_any") == 0)
        state = STATE_IN_DEFAULTS_ALLOW_ANY;
      else if (strcmp (el, "allow_inactive") == 0)
        state = STATE_IN_DEFAULTS_ALLOW_INACTIVE;
      else if (strcmp (el, "allow_active") == 0)
        state = STATE_IN_DEFAULTS_ALLOW_ACTIVE;
      break;

    default:
      break;
    }

  if (state == STATE_NONE)
    {
      g_warning ("skipping unknown tag <%s> at line %d",
                 el, (int) XML_GetCurrentLineNumber (pd->parser));
      state = STATE_UNKNOWN_TAG;
    }

  pd->state = state;
  pd->state_stack[pd->stack_depth] = pd->state;
  pd->stack_depth++;
  return;

error:
  XML_StopParser (pd->parser, FALSE);
}

static gboolean
_validate_icon_name (const gchar *icon_name)
{
  guint n;
  gboolean ret;
  gsize len;

  ret = FALSE;

  len = strlen (icon_name);

  /* check for common suffixes */
  if (g_str_has_suffix (icon_name, ".png"))
    goto out;
  if (g_str_has_suffix (icon_name, ".jpg"))
    goto out;

  /* icon name cannot be a path */
  for (n = 0; n < len; n++)
    {
      if (icon_name [n] == '/')
        {
          goto out;
        }
    }

  ret = TRUE;

out:
  return ret;
}

static void
_cdata (void *data, const char *s, int len)
{
  gchar *str;
  ParserData *pd = data;

  str = g_strndup (s, len);

  switch (pd->state)
    {
    case STATE_IN_ACTION_DESCRIPTION:
      if (pd->elem_lang == NULL)
        {
          g_free (pd->policy_description_nolang);
          pd->policy_description_nolang = str;
          str = NULL;
        }
      else
        {
          g_hash_table_insert (pd->policy_descriptions,
                               g_strdup (pd->elem_lang),
                               str);
          str = NULL;
        }
      break;

    case STATE_IN_ACTION_MESSAGE:
      if (pd->elem_lang == NULL)
        {
          g_free (pd->policy_message_nolang);
          pd->policy_message_nolang = str;
          str = NULL;
        }
      else
        {
          g_hash_table_insert (pd->policy_messages,
                               g_strdup (pd->elem_lang),
                               str);
          str = NULL;
        }
      break;

    case STATE_IN_POLICY_VENDOR:
      g_free (pd->global_vendor);
      pd->global_vendor = str;
      str = NULL;
      break;

    case STATE_IN_POLICY_VENDOR_URL:
      g_free (pd->global_vendor_url);
      pd->global_vendor_url = str;
      str = NULL;
      break;

    case STATE_IN_POLICY_ICON_NAME:
      if (! _validate_icon_name (str))
        {
          g_warning ("Icon name '%s' is invalid", str);
          goto error;
        }
      g_free (pd->global_icon_name);
      pd->global_icon_name = str;
      str = NULL;
      break;

    case STATE_IN_ACTION_VENDOR:
      g_free (pd->vendor);
      pd->vendor = str;
      str = NULL;
      break;

    case STATE_IN_ACTION_VENDOR_URL:
      g_free (pd->vendor_url);
      pd->vendor_url = str;
      str = NULL;
      break;

    case STATE_IN_ACTION_ICON_NAME:
      if (! _validate_icon_name (str))
        {
          g_warning ("Icon name '%s' is invalid", str);
          goto error;
        }

      g_free (pd->icon_name);
      pd->icon_name = str;
      str = NULL;
      break;

    case STATE_IN_DEFAULTS_ALLOW_ANY:
      if (!polkit_implicit_authorization_from_string (str, &pd->implicit_authorization_any))
        goto error;
      break;

    case STATE_IN_DEFAULTS_ALLOW_INACTIVE:
      if (!polkit_implicit_authorization_from_string (str, &pd->implicit_authorization_inactive))
        goto error;
      break;

    case STATE_IN_DEFAULTS_ALLOW_ACTIVE:
      if (!polkit_implicit_authorization_from_string (str, &pd->implicit_authorization_active))
        goto error;
      break;

    case STATE_IN_ANNOTATE:
      g_hash_table_insert (pd->annotations, g_strdup (pd->annotate_key), str);
      str = NULL;
      break;

    default:
      break;
    }

  g_free (str);
  return;

error:
  g_free (str);
  XML_StopParser (pd->parser, FALSE);
}

static void
_end (void *data, const char *el)
{
  ParserData *pd = data;

  g_free (pd->elem_lang);
  pd->elem_lang = NULL;

  switch (pd->state)
    {
    case STATE_IN_ACTION:
      {
        gchar *vendor;
        gchar *vendor_url;
        gchar *icon_name;
        ParsedAction *action;
        PolkitBackendActionPoolPrivate *priv;

        priv = POLKIT_BACKEND_ACTION_POOL_GET_PRIVATE (pd->pool);

        vendor = pd->vendor;
        if (vendor == NULL)
          vendor = pd->global_vendor;

        vendor_url = pd->vendor_url;
        if (vendor_url == NULL)
          vendor_url = pd->global_vendor_url;

        icon_name = pd->icon_name;
        if (icon_name == NULL)
          icon_name = pd->global_icon_name;

        action = g_new0 (ParsedAction, 1);
        action->vendor_name = g_strdup (vendor);
        action->vendor_url = g_strdup (vendor_url);
        action->icon_name = g_strdup (icon_name);
        action->description = g_strdup (pd->policy_description_nolang);
        action->message = g_strdup (pd->policy_message_nolang);

        action->localized_description = pd->policy_descriptions;
        action->localized_message     = pd->policy_messages;
        action->annotations           = pd->annotations;

        action->implicit_authorization_any = pd->implicit_authorization_any;
        action->implicit_authorization_inactive = pd->implicit_authorization_inactive;
        action->implicit_authorization_active = pd->implicit_authorization_active;

        g_hash_table_insert (priv->parsed_actions, g_strdup (pd->action_id),
                             action);

        /* we steal these hash tables */
        pd->annotations = NULL;
        pd->policy_descriptions = NULL;
        pd->policy_messages = NULL;

        break;
      }

    default:
      break;
    }

  --pd->stack_depth;
  if (pd->stack_depth < 0 || pd->stack_depth >= PARSER_MAX_DEPTH)
    {
      g_warning ("reached max depth?");
      goto error;
    }

  if (pd->stack_depth > 0)
    pd->state = pd->state_stack[pd->stack_depth - 1];
  else
    pd->state = STATE_NONE;

  return;

error:
  XML_StopParser (pd->parser, FALSE);
}


/* ---------------------------------------------------------------------------------------------------- */

static gboolean
process_policy_file (PolkitBackendActionPool *pool,
                     const gchar *xml,
                     GError **error)
{
  ParserData pd;
  int xml_res;

  /* clear parser data */
  memset (&pd, 0, sizeof (ParserData));

  pd.pool = pool;

  pd.parser = XML_ParserCreate (NULL);
  pd.stack_depth = 0;
  XML_SetUserData (pd.parser, &pd);
  XML_SetElementHandler (pd.parser, _start, _end);
  XML_SetCharacterDataHandler (pd.parser, _cdata);

  /* init parser data */
  pd.state = STATE_NONE;

  xml_res = XML_Parse (pd.parser, xml, strlen (xml), 1);

  if (xml_res == 0)
    {
      if (XML_GetErrorCode (pd.parser) == XML_ERROR_NO_MEMORY)
        {
          abort ();
        }
      else
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "%d: parse error: %s",
                       (int) XML_GetCurrentLineNumber (pd.parser),
                       XML_ErrorString (XML_GetErrorCode (pd.parser)));
        }
      XML_ParserFree (pd.parser);
      goto error;
    }

  XML_ParserFree (pd.parser);

  pd_unref_data (&pd);
  return TRUE;

error:
  pd_unref_data (&pd);
  return FALSE;
}

/**
 * _localize:
 * @translations: a mapping from xml:lang to the value, e.g. 'da' -> 'Smadre', 'en_CA' -> 'Punch, Aye!'
 * @untranslated: the untranslated value, e.g. 'Punch'
 * @lang: the locale we're interested in, e.g. 'da_DK', 'da', 'en_CA', 'en_US'; basically just $LANG
 * with the encoding cut off. Maybe be NULL.
 *
 * Pick the correct translation to use.
 *
 * Returns: the localized string to use
 */
static const gchar *
_localize (GHashTable *translations,
           const gchar *untranslated,
           const gchar *lang)
{
  const gchar *result;
  gchar **langs;
  guint n;

  if (lang == NULL)
    {
      result = untranslated;
      goto out;
    }

  /* first see if we have the translation */
  result = (const char *) g_hash_table_lookup (translations, (void *) lang);
  if (result != NULL)
    goto out;

  /* we could have a translation for 'da' but lang=='da_DK'; cut off the last part and try again */
  langs = g_get_locale_variants (lang);
  for (n = 0; langs[n] != NULL; n++)
    {
      result = (const char *) g_hash_table_lookup (translations, (void *) langs[n]);
      if (result != NULL)
        break;
    }
  g_strfreev (langs);
  if (result != NULL)
    goto out;

  /* fall back to untranslated */
  result = untranslated;

out:
  return result;
}

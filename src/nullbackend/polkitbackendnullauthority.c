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
#include <grp.h>
#include <string.h>
#include <glib/gstdio.h>

#include "polkitbackendnullauthority.h"

struct _PolkitBackendNullAuthorityPrivate
{
  gint foo;
};

static GList *authority_enumerate_actions  (PolkitBackendAuthority   *authority,
                                            PolkitSubject            *caller,
                                            const gchar              *locale,
                                            GError                  **error);

static void authority_check_authorization (PolkitBackendAuthority        *authority,
                                           PolkitSubject                 *caller,
                                           PolkitSubject                 *subject,
                                           const gchar                   *action_id,
                                           PolkitCheckAuthorizationFlags  flags,
                                           GCancellable                  *cancellable,
                                           GAsyncReadyCallback            callback,
                                           gpointer                       user_data);

static PolkitAuthorizationResult authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                                                       GAsyncResult            *res,
                                                                       GError                 **error);

G_DEFINE_DYNAMIC_TYPE (PolkitBackendNullAuthority, polkit_backend_null_authority,POLKIT_BACKEND_TYPE_AUTHORITY);

static void
polkit_backend_null_authority_init (PolkitBackendNullAuthority *authority)
{
  authority->priv = G_TYPE_INSTANCE_GET_PRIVATE (authority,
                                                 POLKIT_BACKEND_TYPE_NULL_AUTHORITY,
                                                 PolkitBackendNullAuthorityPrivate);
}

static void
polkit_backend_null_authority_finalize (GObject *object)
{
  PolkitBackendNullAuthority *authority;

  authority = POLKIT_BACKEND_NULL_AUTHORITY (object);

  G_OBJECT_CLASS (polkit_backend_null_authority_parent_class)->finalize (object);
}

static void
polkit_backend_null_authority_class_init (PolkitBackendNullAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);

  gobject_class->finalize = polkit_backend_null_authority_finalize;

  authority_class->enumerate_actions               = authority_enumerate_actions;
  authority_class->check_authorization             = authority_check_authorization;
  authority_class->check_authorization_finish      = authority_check_authorization_finish;

  g_type_class_add_private (klass, sizeof (PolkitBackendNullAuthorityPrivate));
}

static void
polkit_backend_null_authority_class_finalize (PolkitBackendNullAuthorityClass *klass)
{
}

static gint
compare_filename (GFile *a, GFile *b)
{
  gchar *a_uri;
  gchar *b_uri;
  gint ret;

  a_uri = g_file_get_uri (a);
  b_uri = g_file_get_uri (b);

  ret = g_strcmp0 (a_uri, b_uri);

  return ret;
}

/* Loads and process all .conf files in /etc/polkit-1/nullbackend.conf.d/ in order */
static void
load_config (gint *out_priority)
{
  GFileEnumerator *enumerator;
  GFile *directory;
  GFileInfo *file_info;
  GError *error;
  GList *files;
  GList *l;

  directory = g_file_new_for_path (PACKAGE_SYSCONF_DIR "/polkit-1/nullbackend.conf.d");

  files = NULL;

  error = NULL;
  enumerator = g_file_enumerate_children (directory,
                                          "standard::*",
                                          G_FILE_QUERY_INFO_NONE,
                                          NULL,
                                          &error);
  if (error != NULL)
    {
      g_warning ("Error enumerating files: %s", error->message);
      goto out;
    }

  while ((file_info = g_file_enumerator_next_file (enumerator, NULL, &error)) != NULL)
    {
      const gchar *name;

      name = g_file_info_get_name (file_info);

      /* only consider files ending in .conf */
      if (g_str_has_suffix (name, ".conf"))
        files = g_list_prepend (files, g_file_get_child (directory, name));

      g_object_unref (file_info);
    }
  if (error != NULL)
    {
      g_warning ("Error enumerating files: %s", error->message);
      goto out;
    }
  g_object_unref (enumerator);

  files = g_list_sort (files, (GCompareFunc) compare_filename);

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
          g_warning ("Error loading file %s: %s", filename, error->message);
          g_error_free (error);
          error = NULL;
        }
      else
        {
          gint priority;

          priority = g_key_file_get_integer (key_file,
                                             "Configuration",
                                             "priority",
                                             &error);
          if (error != NULL)
            {
              /* don't warn, not all config files may have this key */
              g_error_free (error);
            }
          else
            {
              *out_priority = priority;
            }

          g_key_file_free (key_file);
        }

      g_free (filename);
    }

 out:
  g_object_unref (directory);
  g_list_foreach (files, (GFunc) g_object_unref, NULL);
  g_list_free (files);
}

void
polkit_backend_null_authority_register (GIOModule *module)
{
  gint priority;

  priority = -1;

  load_config (&priority);

  polkit_backend_null_authority_register_type (G_TYPE_MODULE (module));

  g_print ("Registering null backend at priority %d\n", priority);

  g_io_extension_point_implement (POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME,
                                  POLKIT_BACKEND_TYPE_NULL_AUTHORITY,
                                  "null backend " PACKAGE_VERSION,
                                  priority);
}

/* ---------------------------------------------------------------------------------------------------- */

static GList *
authority_enumerate_actions  (PolkitBackendAuthority   *authority,
                              PolkitSubject            *caller,
                              const gchar              *locale,
                              GError                  **error)
{
  /* We don't know any actions */
  return NULL;
}

static void
authority_check_authorization (PolkitBackendAuthority        *authority,
                               PolkitSubject                 *caller,
                               PolkitSubject                 *subject,
                               const gchar                   *action_id,
                               PolkitCheckAuthorizationFlags  flags,
                               GCancellable                  *cancellable,
                               GAsyncReadyCallback            callback,
                               gpointer                       user_data)
{
  GSimpleAsyncResult *simple;

  /* complete immediately */
  simple = g_simple_async_result_new (G_OBJECT (authority),
                                      callback,
                                      user_data,
                                      authority_check_authorization);
  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

static PolkitAuthorizationResult
authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                      GAsyncResult            *res,
                                      GError                 **error)
{
  GSimpleAsyncResult *simple;
  PolkitAuthorizationResult result;

  simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == authority_check_authorization);

  /* we always return NOT_AUTHORIZED, never an error */
  result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

 out:
  return result;
}

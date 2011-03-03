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

#include "polkitbackend/polkitbackendconfigsource.h"
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
                                           PolkitDetails                 *details,
                                           PolkitCheckAuthorizationFlags  flags,
                                           GCancellable                  *cancellable,
                                           GAsyncReadyCallback            callback,
                                           gpointer                       user_data);

static PolkitAuthorizationResult *authority_check_authorization_finish (PolkitBackendAuthority  *authority,
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
  G_OBJECT_CLASS (polkit_backend_null_authority_parent_class)->finalize (object);
}

static const gchar *
authority_get_name (PolkitBackendAuthority *authority)
{
  return "null";
}

static const gchar *
authority_get_version (PolkitBackendAuthority *authority)
{
  return PACKAGE_VERSION;
}

static PolkitAuthorityFeatures
authority_get_features (PolkitBackendAuthority *authority)
{
  return POLKIT_AUTHORITY_FEATURES_NONE;
}

static void
polkit_backend_null_authority_class_init (PolkitBackendNullAuthorityClass *klass)
{
  GObjectClass *gobject_class;
  PolkitBackendAuthorityClass *authority_class;

  gobject_class = G_OBJECT_CLASS (klass);
  authority_class = POLKIT_BACKEND_AUTHORITY_CLASS (klass);

  gobject_class->finalize = polkit_backend_null_authority_finalize;

  authority_class->get_name                        = authority_get_name;
  authority_class->get_version                     = authority_get_version;
  authority_class->get_features                    = authority_get_features;
  authority_class->enumerate_actions               = authority_enumerate_actions;
  authority_class->check_authorization             = authority_check_authorization;
  authority_class->check_authorization_finish      = authority_check_authorization_finish;

  g_type_class_add_private (klass, sizeof (PolkitBackendNullAuthorityPrivate));
}

static void
polkit_backend_null_authority_class_finalize (PolkitBackendNullAuthorityClass *klass)
{
}

void
polkit_backend_null_authority_register (GIOModule *module)
{
  gint priority;
  GFile *directory;
  PolkitBackendConfigSource *source;

  directory = g_file_new_for_path (PACKAGE_SYSCONF_DIR "/polkit-1/nullbackend.conf.d");
  source = polkit_backend_config_source_new (directory);

  priority = polkit_backend_config_source_get_integer (source, "Configuration", "Priority", NULL);

  polkit_backend_null_authority_register_type (G_TYPE_MODULE (module));

  g_print ("Registering null backend at priority %d\n", priority);

  g_io_extension_point_implement (POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME,
                                  POLKIT_BACKEND_TYPE_NULL_AUTHORITY,
                                  "null backend " PACKAGE_VERSION,
                                  priority);

  g_object_unref (directory);
  g_object_unref (source);
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
                               PolkitDetails                 *details,
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

static PolkitAuthorizationResult *
authority_check_authorization_finish (PolkitBackendAuthority  *authority,
                                      GAsyncResult            *res,
                                      GError                 **error)
{
  GSimpleAsyncResult *simple;
  PolkitAuthorizationResult *result;

  simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == authority_check_authorization);

  /* we always return NOT_AUTHORIZED, never an error */
  result = polkit_authorization_result_new (FALSE, FALSE, NULL);

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

 out:
  return result;
}

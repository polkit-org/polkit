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

#include "polkitauthorizationresult.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitauthorizationresult
 * @title: PolkitAuthorizationResult
 * @short_description: Result for checking an authorization
 * @stability: Stable
 *
 * This class represents the result you get when checking for an authorization.
 */

/**
 * PolkitAuthorizationResult:
 *
 * The #PolkitAuthorizationResult struct should not be accessed directly.
 */
struct _PolkitAuthorizationResult
{
  GObject parent_instance;

  _PolkitAuthorizationResult *real;

  PolkitDetails *details;
};

struct _PolkitAuthorizationResultClass
{
  GObjectClass parent_class;
};

G_DEFINE_TYPE (PolkitAuthorizationResult, polkit_authorization_result, G_TYPE_OBJECT);

static void
polkit_authorization_result_init (PolkitAuthorizationResult *authorization_result)
{
}

static void
polkit_authorization_result_finalize (GObject *object)
{
  PolkitAuthorizationResult *authorization_result;

  authorization_result = POLKIT_AUTHORIZATION_RESULT (object);

  g_object_unref (authorization_result->real);
  if (authorization_result->details != NULL)
    g_object_unref (authorization_result->details);

  if (G_OBJECT_CLASS (polkit_authorization_result_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_authorization_result_parent_class)->finalize (object);
}

static void
polkit_authorization_result_class_init (PolkitAuthorizationResultClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_authorization_result_finalize;
}

PolkitAuthorizationResult  *
polkit_authorization_result_new_for_real (_PolkitAuthorizationResult *real)
{
  PolkitAuthorizationResult *authorization_result;

  authorization_result = POLKIT_AUTHORIZATION_RESULT (g_object_new (POLKIT_TYPE_AUTHORIZATION_RESULT, NULL));

  authorization_result->real = g_object_ref (real);

  return authorization_result;
}

_PolkitAuthorizationResult *
polkit_authorization_result_get_real (PolkitAuthorizationResult  *authorization_result)
{
  return g_object_ref (authorization_result->real);
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authorization_result_new:
 * @is_authorized: Whether the subject is authorized.
 * @is_challenge: Whether the subject is authorized if more
 * information is provided. Must be %FALSE unless @is_authorized is
 * %TRUE.
 * @details: Must be %NULL unless @is_authorized is %TRUE
 *
 * Creates a new #PolkitAuthorizationResult object.
 *
 * Returns: A #PolkitAuthorizationResult object. Free with g_object_unref().
 */
PolkitAuthorizationResult *
polkit_authorization_result_new (gboolean                   is_authorized,
                                 gboolean                   is_challenge,
                                 PolkitDetails             *details)
{
  PolkitAuthorizationResult *authorization_result;
  _PolkitAuthorizationResult *real;
  EggDBusHashMap *real_details;

  real_details = egg_dbus_hash_map_new (G_TYPE_STRING, g_free, G_TYPE_STRING, g_free);
  if (details != NULL)
    {
      GHashTable *hash;
      GHashTableIter iter;
      gpointer key, value;

      hash = polkit_details_get_hash (details);
      if (hash != NULL)
        {
          g_hash_table_iter_init (&iter, hash);
          while (g_hash_table_iter_next (&iter, &key, &value))
            {
              egg_dbus_hash_map_insert (real_details, g_strdup (key), g_strdup (value));
            }
        }
    }

  real = _polkit_authorization_result_new (is_authorized, is_challenge, real_details);
  g_object_unref (real_details);

  authorization_result = polkit_authorization_result_new_for_real (real);

  g_object_unref (real);

  return authorization_result;
}

/**
 * polkit_authorization_result_get_is_authorized:
 * @result: A #PolkitAuthorizationResult.
 *
 * Gets whether the subject is authorized.
 *
 * Returns: Whether the subject is authorized.
 */
gboolean
polkit_authorization_result_get_is_authorized (PolkitAuthorizationResult *result)
{
  return _polkit_authorization_result_get_is_authorized (result->real);
}

/**
 * polkit_authorization_result_get_is_challenge:
 * @result: A #PolkitAuthorizationResult.
 *
 * Gets whether the subject is authorized if more information is provided.
 *
 * Returns: Whether the subject is authorized if more information is provided.
 */
gboolean
polkit_authorization_result_get_is_challenge (PolkitAuthorizationResult *result)
{
  return _polkit_authorization_result_get_is_challenge (result->real);
}

/**
 * polkit_authorization_result_get_details:
 * @result: A #PolkitAuthorizationResult.
 *
 * Gets the details about the result.
 *
 * Returns: A #PolkitDetails object. This object is owned by @result
 * and should not be freed by the caller.
 */
PolkitDetails *
polkit_authorization_result_get_details (PolkitAuthorizationResult *result)
{
  EggDBusHashMap *real_details;

  if (result->details != NULL)
    goto out;

  real_details = _polkit_authorization_result_get_details (result->real);
  if (real_details != NULL)
    result->details = result->details = polkit_details_new_for_hash (real_details->data);

 out:
  return result->details;
}

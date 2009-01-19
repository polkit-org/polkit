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

#include "polkitidentity.h"
#include "polkitunixuser.h"
#include "polkitunixgroup.h"
#include "polkiterror.h"
#include "polkitprivate.h"

static void
base_init (gpointer g_iface)
{
}

GType
polkit_identity_get_type (void)
{
  static GType iface_type = 0;

  if (iface_type == 0)
    {
      static const GTypeInfo info =
      {
        sizeof (PolkitIdentityIface),
        base_init,              /* base_init      */
        NULL,                   /* base_finalize  */
        NULL,                   /* class_init     */
        NULL,                   /* class_finalize */
        NULL,                   /* class_data     */
        0,                      /* instance_size  */
        0,                      /* n_preallocs    */
        NULL,                   /* instance_init  */
        NULL                    /* value_table    */
      };

      iface_type = g_type_register_static (G_TYPE_INTERFACE, "PolkitIdentity", &info, 0);

      g_type_interface_add_prerequisite (iface_type, G_TYPE_OBJECT);
    }

  return iface_type;
}

guint
polkit_identity_hash (PolkitIdentity *identity)
{
  return POLKIT_IDENTITY_GET_IFACE (identity)->hash (identity);
}

gboolean
polkit_identity_equal (PolkitIdentity *a,
                      PolkitIdentity *b)
{
  if (!g_type_is_a (G_TYPE_FROM_INSTANCE (a), G_TYPE_FROM_INSTANCE (b)))
    return FALSE;

  return POLKIT_IDENTITY_GET_IFACE (a)->equal (a, b);
}

gchar *
polkit_identity_to_string (PolkitIdentity *identity)
{
  return POLKIT_IDENTITY_GET_IFACE (identity)->to_string (identity);
}

PolkitIdentity *
polkit_identity_from_string  (const gchar   *str,
                             GError       **error)
{
  PolkitIdentity *identity;
  guint64 val;
  gchar *endptr;

  g_return_val_if_fail (str != NULL, NULL);

  /* TODO: we could do something with VFuncs like in g_icon_from_string() */

  identity = NULL;

  if (g_str_has_prefix (str, "unix-user:"))
    {
      val = g_ascii_strtoull (str + sizeof "unix-user:" - 1,
                              &endptr,
                              10);
      if (*endptr == '\0')
        identity = polkit_unix_user_new ((uid_t) val);
      else
        identity = polkit_unix_user_new_for_name (str + sizeof "unix-user:" - 1,
                                                 error);
    }
  else if (g_str_has_prefix (str, "unix-group:"))
    {
      val = g_ascii_strtoull (str + sizeof "unix-group:" - 1,
                              &endptr,
                              10);
      if (*endptr == '\0')
        identity = polkit_unix_group_new ((gid_t) val);
      else
        identity = polkit_unix_group_new_for_name (str + sizeof "unix-group:" - 1,
                                                  error);
    }

  if (identity == NULL && (error != NULL && *error == NULL))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Malformed identity string '%s'",
                   str);
    }


  return identity;
}

PolkitIdentity *
polkit_identity_new_for_real (_PolkitIdentity *real)
{
  PolkitIdentity *s;
  const gchar *kind;
  EggDBusHashMap *details;
  EggDBusVariant *variant;

  s = NULL;

  kind = _polkit_identity_get_identity_kind (real);
  details = _polkit_identity_get_identity_details (real);

  if (strcmp (kind, "unix-user") == 0)
    {
      variant = egg_dbus_hash_map_lookup (details, "uid");
      s = polkit_unix_user_new (egg_dbus_variant_get_uint (variant));
    }
  else if (strcmp (kind, "unix-group") == 0)
    {
      variant = egg_dbus_hash_map_lookup (details, "gid");
      s = polkit_unix_group_new (egg_dbus_variant_get_uint (variant));
    }
  else
    {
      g_warning ("Unknown identity kind %s:", kind);
    }

  return s;
}

_PolkitIdentity *
polkit_identity_get_real (PolkitIdentity *identity)
{
  _PolkitIdentity *real;
  const gchar *kind;
  EggDBusHashMap *details;

  real = NULL;
  kind = NULL;
  details = egg_dbus_hash_map_new (G_TYPE_STRING, NULL, EGG_DBUS_TYPE_VARIANT, (GDestroyNotify) g_object_unref);

  if (POLKIT_IS_UNIX_USER (identity))
    {
      kind = "unix-user";
      egg_dbus_hash_map_insert (details,
                                "uid",
                                egg_dbus_variant_new_for_uint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (identity))));
    }
  else if (POLKIT_IS_UNIX_GROUP (identity))
    {
      kind = "unix-group";
      egg_dbus_hash_map_insert (details,
                                "gid",
                                egg_dbus_variant_new_for_uint (polkit_unix_group_get_gid (POLKIT_UNIX_GROUP (identity))));
    }
  else
    {
      g_warning ("Unknown class %s implementing PolkitIdentity", g_type_name (G_TYPE_FROM_INSTANCE (identity)));
    }

  if (kind != NULL)
    {
      real = _polkit_identity_new (kind, details);
    }

  if (details != NULL)
    g_object_unref (details);

  return real;
}


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
#include "polkitunixnetgroup.h"
#include "polkiterror.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitidentity
 * @title: PolkitIdentity
 * @short_description: Type for representing identities
 *
 * #PolkitIdentity is an abstract type for representing one or more
 * identities.
 */

static void
base_init (gpointer g_iface)
{
}

GType
polkit_identity_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
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

      GType iface_type =
        g_type_register_static (G_TYPE_INTERFACE, "PolkitIdentity", &info, 0);

      g_type_interface_add_prerequisite (iface_type, G_TYPE_OBJECT);
      g_once_init_leave (&g_define_type_id__volatile, iface_type);
    }

  return g_define_type_id__volatile;
}

/**
 * polkit_identity_hash:
 * @identity: A #PolkitIdentity.
 *
 * Gets a hash code for @identity that can be used with e.g. g_hash_table_new().
 *
 * Returns: A hash code.
 */
guint
polkit_identity_hash (PolkitIdentity *identity)
{
  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), 0);
  return POLKIT_IDENTITY_GET_IFACE (identity)->hash (identity);
}

/**
 * polkit_identity_equal:
 * @a: A #PolkitIdentity.
 * @b: A #PolkitIdentity.
 *
 * Checks if @a and @b are equal, ie. represent the same identity.
 *
 * This function can be used in e.g. g_hash_table_new().
 *
 * Returns: %TRUE if @a and @b are equal, %FALSE otherwise.
 */
gboolean
polkit_identity_equal (PolkitIdentity *a,
                      PolkitIdentity *b)
{
  g_return_val_if_fail (POLKIT_IS_IDENTITY (a), FALSE);
  g_return_val_if_fail (POLKIT_IS_IDENTITY (b), FALSE);

  if (!g_type_is_a (G_TYPE_FROM_INSTANCE (a), G_TYPE_FROM_INSTANCE (b)))
    return FALSE;

  return POLKIT_IDENTITY_GET_IFACE (a)->equal (a, b);
}

/**
 * polkit_identity_to_string:
 * @identity: A #PolkitIdentity.
 *
 * Serializes @identity to a string that can be used in
 * polkit_identity_from_string().
 *
 * Returns: A string representing @identity. Free with g_free().
 */
gchar *
polkit_identity_to_string (PolkitIdentity *identity)
{
  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), NULL);
  return POLKIT_IDENTITY_GET_IFACE (identity)->to_string (identity);
}

/**
 * polkit_identity_from_string:
 * @str: A string obtained from polkit_identity_to_string().
 * @error: Return location for error.
 *
 * Creates an object from @str that implements the #PolkitIdentity
 * interface.
 *
 * Returns: (allow-none) (transfer full): A #PolkitIdentity or %NULL
 * if @error is set. Free with g_object_unref().
 */
PolkitIdentity *
polkit_identity_from_string  (const gchar   *str,
                             GError       **error)
{
  PolkitIdentity *identity;
  guint64 val;
  gchar *endptr;

  g_return_val_if_fail (str != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  /* TODO: we could do something with VFuncs like in g_icon_from_string() */

  identity = NULL;

  if (g_str_has_prefix (str, "unix-user:"))
    {
      val = g_ascii_strtoull (str + sizeof "unix-user:" - 1,
                              &endptr,
                              10);
      if (*endptr == '\0')
        identity = polkit_unix_user_new ((gint) val);
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
        identity = polkit_unix_group_new ((gint) val);
      else
        identity = polkit_unix_group_new_for_name (str + sizeof "unix-group:" - 1,
                                                  error);
    }
  else if (g_str_has_prefix (str, "unix-netgroup:"))
    {
#ifndef HAVE_SETNETGRENT
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Netgroups are not available on this machine ('%s')",
                   str);
#else
      identity = polkit_unix_netgroup_new (str + sizeof "unix-netgroup:" - 1);
#endif
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

/* Note that this returns a floating value. */
GVariant *
polkit_identity_to_gvariant (PolkitIdentity *identity)
{
  GVariantBuilder builder;
  GVariant *dict;
  const gchar *kind;

  kind = "";

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
  if (POLKIT_IS_UNIX_USER (identity))
    {
      kind = "unix-user";
      g_variant_builder_add (&builder, "{sv}", "uid",
                             g_variant_new_uint32 (polkit_unix_user_get_uid (POLKIT_UNIX_USER (identity))));
    }
  else if (POLKIT_IS_UNIX_GROUP (identity))
    {
      kind = "unix-group";
      g_variant_builder_add (&builder, "{sv}", "gid",
                             g_variant_new_uint32 (polkit_unix_group_get_gid (POLKIT_UNIX_GROUP (identity))));
    }
  else if (POLKIT_IS_UNIX_NETGROUP (identity))
    {
      kind = "unix-netgroup";
      g_variant_builder_add (&builder, "{sv}", "name",
                             g_variant_new_string (polkit_unix_netgroup_get_name (POLKIT_UNIX_NETGROUP (identity))));
    }
  else
    {
      g_warning ("Unknown class %s implementing PolkitIdentity", g_type_name (G_TYPE_FROM_INSTANCE (identity)));
    }

  dict = g_variant_builder_end (&builder);
  return g_variant_new ("(s@a{sv})", kind, dict);
}

static GVariant *
lookup_asv (GVariant            *dict,
            const gchar         *given_key,
            const GVariantType  *given_type,
            GError             **error)
{
  GVariantIter iter;
  const gchar *key;
  GVariant *value;
  GVariant *ret;

  ret = NULL;

  g_variant_iter_init (&iter, dict);
  while (g_variant_iter_next (&iter, "{&sv}", &key, &value))
    {
      if (g_strcmp0 (key, given_key) == 0)
        {
          if (!g_variant_is_of_type (value, given_type))
            {
              gchar *type_string;
              type_string = g_variant_type_dup_string (given_type);
              g_set_error (error,
                           POLKIT_ERROR,
                           POLKIT_ERROR_FAILED,
                           "Value for key `%s' found but is of type %s and type %s was expected",
                           given_key,
                           g_variant_get_type_string (value),
                           type_string);
              g_free (type_string);
              g_variant_unref (value);
              goto out;
            }
          ret = value;
          goto out;
        }
      g_variant_unref (value);
    }

 out:
  if (ret == NULL)
    {
      gchar *type_string;
      type_string = g_variant_type_dup_string (given_type);
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Didn't find value for key `%s' of type %s",
                   given_key,
                   type_string);
      g_free (type_string);
    }

  return ret;
}

PolkitIdentity *
polkit_identity_new_for_gvariant (GVariant  *variant,
                                  GError    **error)
{
  PolkitIdentity *ret;
  const gchar *kind;
  GVariant *details_gvariant;

  ret = NULL;

  g_variant_get (variant,
                 "(&s@a{sv})",
                 &kind,
                 &details_gvariant);

  if (g_strcmp0 (kind, "unix-user") == 0)
    {
      GVariant *v;
      guint32 uid;

      v = lookup_asv (details_gvariant, "uid", G_VARIANT_TYPE_UINT32, error);
      if (v == NULL)
        {
          g_prefix_error (error, "Error parsing unix-user identity: ");
          goto out;
        }
      uid = g_variant_get_uint32 (v);
      g_variant_unref (v);

      ret = polkit_unix_user_new (uid);
    }
  else if (g_strcmp0 (kind, "unix-group") == 0)
    {
      GVariant *v;
      guint32 gid;

      v = lookup_asv (details_gvariant, "gid", G_VARIANT_TYPE_UINT32, error);
      if (v == NULL)
        {
          g_prefix_error (error, "Error parsing unix-user identity: ");
          goto out;
        }
      gid = g_variant_get_uint32 (v);
      g_variant_unref (v);

      ret = polkit_unix_group_new (gid);
    }
  else if (g_strcmp0 (kind, "unix-netgroup") == 0)
    {
      GVariant *v;
      const char *name;

#ifndef HAVE_SETNETGRENT
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Netgroups are not available on this machine");
      goto out;
#else

      v = lookup_asv (details_gvariant, "name", G_VARIANT_TYPE_STRING, error);
      if (v == NULL)
        {
          g_prefix_error (error, "Error parsing net identity: ");
          goto out;
        }
      name = g_variant_get_string (v, NULL);
      ret = polkit_unix_netgroup_new (name);
      g_variant_unref (v);
#endif
    }
  else
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Unknown identity of kind `%s'",
                   kind);
    }

 out:
  g_variant_unref (details_gvariant);
  return ret;
}

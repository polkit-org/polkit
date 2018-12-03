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
#include <pwd.h>
#include <errno.h>
#include "polkitunixuser.h"
#include "polkitidentity.h"
#include "polkiterror.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitunixuser
 * @title: PolkitUnixUser
 * @short_description: Unix users
 *
 * An object representing a user identity on a UNIX system.
 */

/**
 * PolkitUnixUser:
 *
 * The #PolkitUnixUser struct should not be accessed directly.
 */
struct _PolkitUnixUser
{
  GObject parent_instance;

  gint uid;
  gchar *name;
};

struct _PolkitUnixUserClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_UID,
};

static void identity_iface_init (PolkitIdentityIface *identity_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixUser, polkit_unix_user, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_IDENTITY, identity_iface_init)
                         );

static void
polkit_unix_user_init (PolkitUnixUser *unix_user)
{
  unix_user->uid = -1;  /* (uid_t) -1 is not a valid UID under Linux */
  unix_user->name = NULL;
}

static void
polkit_unix_user_finalize (GObject *object)
{
  PolkitUnixUser *unix_user = POLKIT_UNIX_USER (object);

  g_free(unix_user->name);

  G_OBJECT_CLASS (polkit_unix_user_parent_class)->finalize (object);
}

static void
polkit_unix_user_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
  PolkitUnixUser *unix_user = POLKIT_UNIX_USER (object);

  switch (prop_id)
    {
    case PROP_UID:
      g_value_set_int (value, unix_user->uid);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_user_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
  PolkitUnixUser *unix_user = POLKIT_UNIX_USER (object);
  gint val;

  switch (prop_id)
    {
    case PROP_UID:
      val = g_value_get_int (value);
      g_return_if_fail (val != -1);
      unix_user->uid = val;
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_user_class_init (PolkitUnixUserClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_unix_user_finalize;
  gobject_class->get_property = polkit_unix_user_get_property;
  gobject_class->set_property = polkit_unix_user_set_property;

  /**
   * PolkitUnixUser:uid:
   *
   * The UNIX user id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_UID,
                                   g_param_spec_int ("uid",
                                                     "User ID",
                                                     "The UNIX user ID",
                                                     G_MININT,
                                                     G_MAXINT,
                                                     -1,
                                                     G_PARAM_CONSTRUCT |
                                                     G_PARAM_READWRITE |
                                                     G_PARAM_STATIC_NAME |
                                                     G_PARAM_STATIC_BLURB |
                                                     G_PARAM_STATIC_NICK));

}

/**
 * polkit_unix_user_get_uid:
 * @user: A #PolkitUnixUser.
 *
 * Gets the UNIX user id for @user.
 *
 * Returns: A UNIX user id.
 */
gint
polkit_unix_user_get_uid (PolkitUnixUser *user)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_USER (user), -1);
  return user->uid;
}

/**
 * polkit_unix_user_set_uid:
 * @user: A #PolkitUnixUser.
 * @uid: A UNIX user id.
 *
 * Sets @uid for @user.
 */
void
polkit_unix_user_set_uid (PolkitUnixUser *user,
                          gint uid)
{
  g_return_if_fail (POLKIT_IS_UNIX_USER (user));
  g_return_if_fail (uid != -1);
  user->uid = uid;
}

/**
 * polkit_unix_user_new:
 * @uid: A UNIX user id.
 *
 * Creates a new #PolkitUnixUser object for @uid.
 *
 * Returns: (transfer full): A #PolkitUnixUser object. Free with g_object_unref().
 */
PolkitIdentity *
polkit_unix_user_new (gint uid)
{
  g_return_val_if_fail (uid != -1, NULL);

  return POLKIT_IDENTITY (g_object_new (POLKIT_TYPE_UNIX_USER,
                                        "uid", uid,
                                        NULL));
}

/**
 * polkit_unix_user_new_for_name:
 * @name: A UNIX user name.
 * @error: Return location for error.
 *
 * Creates a new #PolkitUnixUser object for a user with the user name
 * @name.
 *
 * Returns: (allow-none) (transfer full): A #PolkitUnixUser object or %NULL if @error is set.
 */
PolkitIdentity *
polkit_unix_user_new_for_name (const gchar    *name,
                               GError        **error)
{
  struct passwd *passwd;
  PolkitIdentity *identity;

  g_return_val_if_fail (name != NULL, NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  identity = NULL;

  passwd = getpwnam (name);
  if (passwd == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "No UNIX user with name %s: %s",
                   name,
                   g_strerror (errno));
      goto out;
    }

  identity = polkit_unix_user_new (passwd->pw_uid);

 out:
  return identity;
}

/**
 * polkit_unix_user_get_name:
 * @user: A #PolkitUnixUser.
 *
 * Get the user's name.
 *
 * Returns: (allow-none) (transfer none): User name string or %NULL if user uid not found.
 */
const gchar *
polkit_unix_user_get_name (PolkitUnixUser *user)
{
  if (user->name == NULL)
    {
      struct passwd *passwd;
      passwd = getpwuid (user->uid);

      if (passwd != NULL)
        user->name = g_strdup(passwd->pw_name);
    }

  return user->name;
}

static gboolean
polkit_unix_user_equal (PolkitIdentity *a,
                        PolkitIdentity *b)
{
  PolkitUnixUser *user_a;
  PolkitUnixUser *user_b;

  user_a = POLKIT_UNIX_USER (a);
  user_b = POLKIT_UNIX_USER (b);

  return user_a->uid == user_b->uid;
}

static guint
polkit_unix_user_hash (PolkitIdentity *identity)
{
  PolkitUnixUser *user;

  user = POLKIT_UNIX_USER (identity);

  return g_direct_hash (GINT_TO_POINTER (((gint) (user->uid)) * 2));
}

static gchar *
polkit_unix_user_to_string (PolkitIdentity *identity)
{
  PolkitUnixUser *user = POLKIT_UNIX_USER (identity);
  const gchar *user_name = polkit_unix_user_get_name(user);

  if (user_name != NULL)
    return g_strdup_printf ("unix-user:%s", user_name);
  else
    return g_strdup_printf ("unix-user:%d", user->uid);
}

static void
identity_iface_init (PolkitIdentityIface *identity_iface)
{
  identity_iface->hash      = polkit_unix_user_hash;
  identity_iface->equal     = polkit_unix_user_equal;
  identity_iface->to_string = polkit_unix_user_to_string;
}

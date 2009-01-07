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
#include "polkitunixuser.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitunixuser
 * @title: PolkitUnixUser
 * @short_description: Unix users
 *
 * Encapsulates a UNIX user.
 */

struct _PolkitUnixUser
{
  GObject parent_instance;

  uid_t uid;
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

static void subject_iface_init (PolkitSubjectIface *subject_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixUser, polkit_unix_user, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_unix_user_init (PolkitUnixUser *unix_user)
{
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
      g_value_set_uint (value, unix_user->uid);
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

  switch (prop_id)
    {
    case PROP_UID:
      unix_user->uid = g_value_get_uint (value);
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

  gobject_class->get_property = polkit_unix_user_get_property;
  gobject_class->set_property = polkit_unix_user_set_property;

  /**
   * PolkitUnixUser:uid:
   *
   * The UNIX user id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_UID,
                                   g_param_spec_uint ("uid",
                                                      "User ID",
                                                      "The UNIX user ID",
                                                      0,
                                                      G_MAXUINT,
                                                      0,
                                                      G_PARAM_CONSTRUCT |
                                                      G_PARAM_READWRITE |
                                                      G_PARAM_STATIC_NAME |
                                                      G_PARAM_STATIC_BLURB |
                                                      G_PARAM_STATIC_NICK));

}

uid_t
polkit_unix_user_get_uid (PolkitUnixUser *user)
{
  return user->uid;
}

void
polkit_unix_user_set_uid (PolkitUnixUser *user,
                          uid_t uid)
{
  user->uid = uid;
}

PolkitSubject *
polkit_unix_user_new (uid_t uid)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_USER,
                                       "uid", uid,
                                       NULL));
}

static gboolean
polkit_unix_user_equal (PolkitSubject *a,
                        PolkitSubject *b)
{
  PolkitUnixUser *user_a;
  PolkitUnixUser *user_b;

  user_a = POLKIT_UNIX_USER (a);
  user_b = POLKIT_UNIX_USER (b);

  return user_a->uid == user_b->uid;
}

static gchar *
polkit_unix_user_to_string (PolkitSubject *subject)
{
  PolkitUnixUser *user = POLKIT_UNIX_USER (subject);
  struct passwd *passwd;

  passwd = getpwuid (user->uid);

  if (passwd == NULL)
    return g_strdup_printf ("unix-user:%d", user->uid);
  else
    return g_strdup_printf ("unix-user:%s", passwd->pw_name);
}

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->equal     = polkit_unix_user_equal;
  subject_iface->to_string = polkit_unix_user_to_string;
}

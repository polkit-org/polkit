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

#include "polkitsubject.h"
#include "polkitunixuser.h"
#include "polkitunixgroup.h"
#include "polkitunixprocess.h"
#include "polkitunixsession.h"
#include "polkitsystembusname.h"
#include "polkiterror.h"
#include "polkitprivate.h"

static void
base_init (gpointer g_iface)
{
}

GType
polkit_subject_get_type (void)
{
  static GType iface_type = 0;

  if (iface_type == 0)
    {
      static const GTypeInfo info =
      {
        sizeof (PolkitSubjectIface),
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

      iface_type = g_type_register_static (G_TYPE_INTERFACE, "PolkitSubject", &info, 0);

      g_type_interface_add_prerequisite (iface_type, G_TYPE_OBJECT);
    }

  return iface_type;
}

gboolean
polkit_subject_equal (PolkitSubject *a,
                      PolkitSubject *b)
{
  if (!g_type_is_a (G_TYPE_FROM_INSTANCE (a), G_TYPE_FROM_INSTANCE (b)))
    return FALSE;

  return POLKIT_SUBJECT_GET_IFACE (a)->equal (a, b);
}

gchar *
polkit_subject_to_string (PolkitSubject *subject)
{
  return POLKIT_SUBJECT_GET_IFACE (subject)->to_string (subject);
}

PolkitSubject *
polkit_subject_from_string  (const gchar   *str,
                             GError       **error)
{
  PolkitSubject *subject;
  guint64 val;
  gchar *endptr;

  g_return_val_if_fail (str != NULL, NULL);

  /* TODO: we could do something with VFuncs like in g_icon_from_string() */

  subject = NULL;

  if (g_str_has_prefix (str, "unix-user:"))
    {
      val = g_ascii_strtoull (str + sizeof "unix-user:" - 1,
                              &endptr,
                              10);
      if (*endptr == '\0')
        subject = polkit_unix_user_new ((uid_t) val);
      else
        subject = polkit_unix_user_new_for_name (str + sizeof "unix-user:" - 1,
                                                 error);
    }
  else if (g_str_has_prefix (str, "unix-group:"))
    {
      val = g_ascii_strtoull (str + sizeof "unix-group:" - 1,
                              &endptr,
                              10);
      if (*endptr == '\0')
        subject = polkit_unix_group_new ((gid_t) val);
      else
        subject = polkit_unix_group_new_for_name (str + sizeof "unix-group:" - 1,
                                                  error);
    }
  else if (g_str_has_prefix (str, "unix-process:"))
    {
      val = g_ascii_strtoull (str + sizeof "unix-process:" - 1,
                              &endptr,
                              10);
      if (*endptr == '\0')
        {
          subject = polkit_unix_process_new ((pid_t) val);
          if (polkit_unix_process_get_start_time (POLKIT_UNIX_PROCESS (subject)) == 0)
            {
              g_object_unref (subject);
              subject = NULL;
              g_set_error (error,
                           POLKIT_ERROR,
                           POLKIT_ERROR_FAILED,
                           "No process with pid %" G_GUINT64_FORMAT,
                           val);
            }
        }
    }
  else if (g_str_has_prefix (str, "system-bus-name:"))
    {
      subject = polkit_system_bus_name_new (str + sizeof "system-bus-name:" - 1);
    }

  if (subject == NULL && (error != NULL && *error == NULL))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Malformed subject string '%s'",
                   str);
    }


  return subject;
}

PolkitSubject *
polkit_subject_new_for_real (_PolkitSubject *real)
{
  PolkitSubject *s;
  const gchar *kind;
  EggDBusHashMap *details;
  EggDBusVariant *variant;
  EggDBusVariant *variant2;

  s = NULL;

  kind = _polkit_subject_get_subject_kind (real);
  details = _polkit_subject_get_subject_details (real);

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
  else if (strcmp (kind, "unix-process") == 0)
    {
      variant = egg_dbus_hash_map_lookup (details, "pid");
      variant2 = egg_dbus_hash_map_lookup (details, "start-time");
      s = polkit_unix_process_new_full (egg_dbus_variant_get_uint (variant),
                                        egg_dbus_variant_get_uint64 (variant2));
    }
  else if (strcmp (kind, "unix-session") == 0)
    {
      variant = egg_dbus_hash_map_lookup (details, "session-id");
      s = polkit_unix_session_new (egg_dbus_variant_get_string (variant));
    }
  else if (strcmp (kind, "system-bus-name") == 0)
    {
      variant = egg_dbus_hash_map_lookup (details, "name");
      s = polkit_system_bus_name_new (egg_dbus_variant_get_string (variant));
    }
  else
    {
      g_warning ("Unknown subject kind %s:", kind);
    }

  return s;
}

_PolkitSubject *
polkit_subject_get_real (PolkitSubject *subject)
{
  _PolkitSubject *real;
  const gchar *kind;
  EggDBusHashMap *details;

  real = NULL;
  kind = NULL;
  details = egg_dbus_hash_map_new (G_TYPE_STRING, NULL, EGG_DBUS_TYPE_VARIANT, (GDestroyNotify) g_object_unref);

  if (POLKIT_IS_UNIX_USER (subject))
    {
      kind = "unix-user";
      egg_dbus_hash_map_insert (details,
                                "uid",
                                egg_dbus_variant_new_for_uint (polkit_unix_user_get_uid (POLKIT_UNIX_USER (subject))));
    }
  else if (POLKIT_IS_UNIX_GROUP (subject))
    {
      kind = "unix-group";
      egg_dbus_hash_map_insert (details,
                                "gid",
                                egg_dbus_variant_new_for_uint (polkit_unix_group_get_gid (POLKIT_UNIX_GROUP (subject))));
    }
  else if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      kind = "unix-process";
      egg_dbus_hash_map_insert (details,
                                "pid",
                                egg_dbus_variant_new_for_uint (polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (subject))));
      egg_dbus_hash_map_insert (details,
                                "start-time",
                                egg_dbus_variant_new_for_uint64 (polkit_unix_process_get_start_time (POLKIT_UNIX_PROCESS (subject))));
    }
  else if (POLKIT_IS_UNIX_SESSION (subject))
    {
      kind = "unix-session";
      egg_dbus_hash_map_insert (details,
                                "session-id",
                                egg_dbus_variant_new_for_string (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (subject))));
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      kind = "system-bus-name";
      egg_dbus_hash_map_insert (details,
                                "name",
                                egg_dbus_variant_new_for_string (polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject))));
    }
  else
    {
      g_warning ("Unknown class %s implementing PolkitSubject", g_type_name (G_TYPE_FROM_INSTANCE (subject)));
    }

  if (kind != NULL)
    {
      real = _polkit_subject_new (kind, details);
    }

  if (details != NULL)
    g_object_unref (details);

  return real;
}


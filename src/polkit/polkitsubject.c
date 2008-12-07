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
#include "polkitbindings.h"
#include "polkitsubject.h"

/**
 * SECTION:polkitsubject
 * @title: PolkitSubject
 * @short_description: Subjects
 *
 * The #PolkitSubject type is used for representing subject such as
 * users, groups and processes.
 */

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

      g_type_interface_add_prerequisite (iface_type, EGG_DBUS_TYPE_STRUCTURE);
    }

  return iface_type;
}

/**
 * polkit_subject_new_for_unix_process:
 * @unix_process_id: The Process ID.
 *
 * Constructs a new #PolkitSubject for a the UNIX process with PID @process_id.
 *
 * Returns: A #PolkitSubject.
 */
PolkitSubject *
polkit_subject_new_for_unix_process (pid_t unix_process_id)
{
  GValue *values;
  EggDBusHashTable *properties;

  properties = g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      (GDestroyNotify) g_free,
                                      (GDestroyNotify) g_object_unref);
  egg_dbus_hash_table_set_signature (properties, "s", "v");

  g_hash_table_insert (properties,
                       g_strdup ("unix-process-id"),
                       egg_dbus_variant_new_for_uint32 (unix_process_id));

  values = g_new0 (GValue, 2);
  g_value_init (&(values[0]), G_TYPE_STRING);
  g_value_set_string (&(values[0]), "unix-process");
  g_value_init (&(values[1]), EGG_DBUS_TYPE_HASH_TABLE);
  g_value_set_boxed (&(values[1]), properties);

  return POLKIT_SUBJECT (egg_dbus_structure_new ("(sa{sv})", 2, values));
}

/**
 * polkit_subject_new_for_unix_user:
 * @unix_user_id: The User ID.
 *
 * Constructs a new #PolkitSubject for a the UNIX user with UID @user_id.
 *
 * Returns: A #PolkitSubject.
 */
PolkitSubject *
polkit_subject_new_for_unix_user (uid_t unix_user_id)
{
  GValue *values;
  EggDBusHashTable *properties;

  properties = g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      (GDestroyNotify) g_free,
                                      (GDestroyNotify) g_object_unref);
  egg_dbus_hash_table_set_signature (properties, "s", "v");

  g_hash_table_insert (properties,
                       g_strdup ("unix-user-id"),
                       egg_dbus_variant_new_for_uint32 (unix_user_id));

  values = g_new0 (GValue, 2);
  g_value_init (&(values[0]), G_TYPE_STRING);
  g_value_set_string (&(values[0]), "unix-user");
  g_value_init (&(values[1]), EGG_DBUS_TYPE_HASH_TABLE);
  g_value_set_boxed (&(values[1]), properties);

  return POLKIT_SUBJECT (egg_dbus_structure_new ("(sa{sv})", 2, values));
}

/**
 * polkit_subject_new_for_unix_group:
 * @unix_group_id: The Group ID.
 *
 * Constructs a new #PolkitSubject for a the UNIX group with GID @group_id.
 *
 * Returns: A #PolkitSubject.
 */
PolkitSubject *
polkit_subject_new_for_unix_group (gid_t unix_group_id)
{
  GValue *values;
  EggDBusHashTable *properties;

  properties = g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      (GDestroyNotify) g_free,
                                      (GDestroyNotify) g_object_unref);
  egg_dbus_hash_table_set_signature (properties, "s", "v");

  g_hash_table_insert (properties,
                       g_strdup ("unix-group-id"),
                       egg_dbus_variant_new_for_uint32 (unix_group_id));

  values = g_new0 (GValue, 2);
  g_value_init (&(values[0]), G_TYPE_STRING);
  g_value_set_string (&(values[0]), "unix-group");
  g_value_init (&(values[1]), EGG_DBUS_TYPE_HASH_TABLE);
  g_value_set_boxed (&(values[1]), properties);

  return POLKIT_SUBJECT (egg_dbus_structure_new ("(sa{sv})", 2, values));
}

/**
 * polkit_subject_get_kind:
 * @subject: A #PolkitSubject.
 *
 * Gets the kind of @subject.
 *
 * Returns: A #PolkitSubjectKind.
 */
PolkitSubjectKind
polkit_subject_get_kind (PolkitSubject *subject)
{
  const gchar *kind_str;
  PolkitSubjectKind kind;

  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), -1);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (subject)), "(sa{sv})") == 0, -1);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (subject),
                                  0, &kind_str,
                                  -1);

  if (strcmp (kind_str, "unix-process") == 0)
    kind = POLKIT_SUBJECT_KIND_UNIX_PROCESS;
  else if (strcmp (kind_str, "unix-user") == 0)
    kind = POLKIT_SUBJECT_KIND_UNIX_USER;
  else if (strcmp (kind_str, "unix-group") == 0)
    kind = POLKIT_SUBJECT_KIND_UNIX_GROUP;
  else
    {
      g_warning ("unknown kind str '%s'", kind_str);
      kind = -1;
    }

  return kind;
}

/**
 * polkit_subject_equal:
 * @a: A #PolkitSubject.
 * @b: A #PolkitSubject.
 *
 * Checks if the two subjects @a and @b are equal.
 *
 * Returns: %TRUE if @a and @b are equal, %FALSE otherwise.
 **/
gboolean
polkit_subject_equal (PolkitSubject *a,
                      PolkitSubject *b)
{
  gboolean ret;
  PolkitSubjectKind kind_a;
  PolkitSubjectKind kind_b;

  g_return_val_if_fail (POLKIT_IS_SUBJECT (a), FALSE);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (b), FALSE);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (a)), "(sa{sv})") == 0, FALSE);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (b)), "(sa{sv})") == 0, FALSE);

  ret = FALSE;

  kind_a = polkit_subject_get_kind (a);
  kind_b = polkit_subject_get_kind (b);

  if (kind_a != kind_b)
    goto out;

  switch (kind_a)
    {
    case POLKIT_SUBJECT_KIND_UNIX_PROCESS:
      if (polkit_subject_unix_process_get_id (a) == polkit_subject_unix_process_get_id (b))
        ret = TRUE;
      break;

    case POLKIT_SUBJECT_KIND_UNIX_USER:
      if (polkit_subject_unix_user_get_id (a) == polkit_subject_unix_user_get_id (b))
        ret = TRUE;
      break;

    case POLKIT_SUBJECT_KIND_UNIX_GROUP:
      if (polkit_subject_unix_group_get_id (a) == polkit_subject_unix_group_get_id (b))
        ret = TRUE;
      break;

    default:
      /* get_kind() will already have warned */
      goto out;
    }

 out:
  return ret;
}

/**
 * polkit_subject_unix_process_get_id:
 * @subject: A #PolkitSubject of the @POLKIT_SUBJECT_KIND_UNIX_PROCESS kind.
 *
 * Gets the UNIX process id for @subject.
 *
 * Returns: UNIX process id.
 **/
pid_t
polkit_subject_unix_process_get_id (PolkitSubject *subject)
{
  EggDBusHashTable *value;
  EggDBusVariant *variant;
  pid_t pid;

  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), 0);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (subject)), "(sa{sv})") == 0, 0);
  g_return_val_if_fail (polkit_subject_get_kind (subject) != POLKIT_SUBJECT_KIND_UNIX_PROCESS, 0);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (subject),
                1, &value,
                -1);

  variant = g_hash_table_lookup (value, "unix-process-id");
  pid = (pid_t) egg_dbus_variant_get_uint32 (variant);

  return pid;
}

/**
 * polkit_subject_unix_user_get_id:
 * @subject: A #PolkitSubject of the @POLKIT_SUBJECT_KIND_UNIX_USER kind.
 *
 * Gets the UNIX user id for @subject.
 *
 * Returns: UNIX user id.
 **/
uid_t
polkit_subject_unix_user_get_id (PolkitSubject *subject)
{
  EggDBusHashTable *value;
  EggDBusVariant *variant;
  uid_t uid;

  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), 0);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (subject)), "(sa{sv})") == 0, 0);
  g_return_val_if_fail (polkit_subject_get_kind (subject) != POLKIT_SUBJECT_KIND_UNIX_USER, 0);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (subject),
                1, &value,
                -1);

  variant = g_hash_table_lookup (value, "unix-user-id");
  uid = (uid_t) egg_dbus_variant_get_uint32 (variant);

  return uid;
}

/**
 * polkit_subject_unix_group_get_id:
 * @subject: A #PolkitSubject of the @POLKIT_SUBJECT_KIND_UNIX_GROUP kind.
 *
 * Gets the UNIX group id for @subject.
 *
 * Returns: UNIX group id.
 **/
gid_t
polkit_subject_unix_group_get_id (PolkitSubject *subject)
{
  EggDBusHashTable *value;
  EggDBusVariant *variant;
  gid_t gid;

  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), 0);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (subject)), "(sa{sv})") == 0, 0);
  g_return_val_if_fail (polkit_subject_get_kind (subject) != POLKIT_SUBJECT_KIND_UNIX_GROUP, 0);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (subject),
                1, &value,
                -1);

  variant = g_hash_table_lookup (value, "unix-group-id");
  gid = (gid_t) egg_dbus_variant_get_uint32 (variant);

  return gid;
}


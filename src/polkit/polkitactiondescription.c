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
#include "polkitactiondescription.h"

/**
 * SECTION:polkitactiondescription
 * @title: PolkitActionDescription
 * @short_description: Descriptions of actions
 *
 * The #PolkitActionDescription type is used to described registered PolicyKit actions.
 */

static void
base_init (gpointer g_iface)
{
}

GType
polkit_action_description_get_type (void)
{
  static GType iface_type = 0;

  if (iface_type == 0)
    {
      static const GTypeInfo info =
      {
        sizeof (PolkitActionDescriptionIface),
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

      iface_type = g_type_register_static (G_TYPE_INTERFACE, "PolkitActionDescription", &info, 0);

      g_type_interface_add_prerequisite (iface_type, EGG_DBUS_TYPE_STRUCTURE);
    }

  return iface_type;
}

#define ACTION_DESCRIPTION_SIGNATURE "(ssssssa{ss})"

/**
 * polkit_action_description_get_action_id:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the action identifer for @action_description.
 *
 * Returns: The action identifier for @action_description.
 */
const gchar *
polkit_action_description_get_action_id (PolkitActionDescription *action_description)
{
  const gchar *s;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  0, &s,
                                  -1);

  return s;
}

/**
 * polkit_action_description_get_description:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets a human readable description of @action_description.
 *
 * Returns: The human readable description for @action_description or %NULL if not set.
 */
const gchar *
polkit_action_description_get_description (PolkitActionDescription *action_description)
{
  const gchar *s;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  1, &s,
                                  -1);

  return strlen (s) > 0 ? s : NULL;
}

/**
 * polkit_action_description_get_message:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the message shown for @action_description.
 *
 * Returns: The message for @action_description or %NULL if not set.
 */
const gchar *
polkit_action_description_get_message (PolkitActionDescription *action_description)
{
  const gchar *s;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  2, &s,
                                  -1);

  return strlen (s) > 0 ? s : NULL;
}

/**
 * polkit_action_description_get_vendor_name:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the name of the vendor for @action_description.
 *
 * Returns: The vendor of @action_description or %NULL if not set.
 */
const gchar *
polkit_action_description_get_vendor_name (PolkitActionDescription *action_description)
{
  const gchar *s;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  3, &s,
                                  -1);

  return strlen (s) > 0 ? s : NULL;
}

/**
 * polkit_action_description_get_vendor_url:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the vendor URL for @action_description.
 *
 * Returns: The vendor URL for @action_description or %NULL if not set.
 */
const gchar *
polkit_action_description_get_vendor_url (PolkitActionDescription *action_description)
{
  const gchar *s;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  4, &s,
                                  -1);

  return strlen (s) > 0 ? s : NULL;
}

/**
 * polkit_action_description_get_icon:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the #GIcon for @action_description.
 *
 * Returns: A #GIcon (free with g_object_unref() when done with it) or %NULL if not set.
 */
GIcon *
polkit_action_description_get_icon (PolkitActionDescription *action_description)
{
  const gchar *s;
  GIcon *icon;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  5, &s,
                                  -1);

  if (strlen (s) > 0)
    {
      icon = NULL;
    }
  else
    {
      GError *error;

      error = NULL;
      icon = g_icon_new_for_string (s, &error);
      if (icon == NULL)
        {
          g_warning ("Error getting icon for action description: %s", error->message);
          g_error_free (error);
        }
    }

  return icon;
}

/**
 * polkit_action_description_get_annotations:
 * @action_description: A #PolkitActionDescription.
 *
 * Gets the annotations for @action_description.
 *
 * Returns: A #GHashTable from strings to strings with the annotations
 * for @action_description. Do not destroy or unref this hash table;
 * it is owned by @action_description.
 */
GHashTable *
polkit_action_description_get_annotations (PolkitActionDescription *action_description)
{
  GHashTable *hash;

  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (action_description)), ACTION_DESCRIPTION_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (action_description),
                                  6, &hash,
                                  -1);

  return hash;
}


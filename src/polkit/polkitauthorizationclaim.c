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
#include <string.h>
#include "polkitauthorizationclaim.h"
#include "polkitsubject.h"

/**
 * SECTION:polkitauthorizationclaim
 * @title: PolkitAuthorizationClaim
 * @short_description: Authorization Claim
 *
 * Represents an authorization claim.
 */

static void
base_init (gpointer g_iface)
{
}

GType
polkit_authorization_claim_get_type (void)
{
  static GType iface_type = 0;

  if (iface_type == 0)
    {
      static const GTypeInfo info =
      {
        sizeof (PolkitAuthorizationClaimIface),
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

      iface_type = g_type_register_static (G_TYPE_INTERFACE, "PolkitAuthorizationClaim", &info, 0);

      g_type_interface_add_prerequisite (iface_type, EGG_DBUS_TYPE_STRUCTURE);
    }

  return iface_type;
}

#define AUTHORIZATION_CLAIM_SIGNATURE "((sa{sv})sa{ss})"

/**
 * polkit_authorization_claim_new:
 * @subject: The subject the claim is for.
 * @action_id: The action identifier for the PolicyKit action the claim is about.
 *
 * Constructs a new #PolkitAuthorizationClaim representing a claim that @subject is authorized for @action_id.
 *
 * Returns: A #PolkitAuthorizationClaim.
 */
PolkitAuthorizationClaim *
polkit_authorization_claim_new (PolkitSubject *subject,
                                const gchar   *action_id)
{
  GValue *values;
  EggDBusHashTable *attributes;

  attributes = g_hash_table_new_full (g_str_hash,
                                      g_str_equal,
                                      (GDestroyNotify) g_free,
                                      (GDestroyNotify) g_object_unref);
  egg_dbus_hash_table_set_signature (attributes, "s", "s");

  values = g_new0 (GValue, 3);
  g_value_init (&(values[0]), POLKIT_TYPE_SUBJECT);
  g_value_set_object (&(values[0]), subject);
  g_value_init (&(values[1]), G_TYPE_STRING);
  g_value_set_string (&(values[1]), action_id);
  g_value_init (&(values[2]), EGG_DBUS_TYPE_HASH_TABLE);
  g_value_take_boxed (&(values[2]), attributes);

  return POLKIT_AUTHORIZATION_CLAIM (egg_dbus_structure_new (AUTHORIZATION_CLAIM_SIGNATURE, 3, values));
}

/**
 * polkit_authorization_claim_get_subject:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 *
 * Gets the subject for @authorization_claim.
 *
 * Returns: A #PolkitSubject instance owned by @authorization_claim. Do not free.
 **/
PolkitSubject *
polkit_authorization_claim_get_subject (PolkitAuthorizationClaim *authorization_claim)
{
  PolkitSubject *subject;

  g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (authorization_claim)), AUTHORIZATION_CLAIM_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (authorization_claim),
                                  0, &subject,
                                  -1);

  return subject;
}

/**
 * polkit_authorization_claim_get_action_id:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 *
 * Gets the action identifier for @authorization_claim.
 *
 * Returns: A string owned by @authorization_claim. Do not free.
 **/
const gchar *
polkit_authorization_claim_get_action_id (PolkitAuthorizationClaim *authorization_claim)
{
  const gchar *action_id;

  g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (authorization_claim)), AUTHORIZATION_CLAIM_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (authorization_claim),
                                  1, &action_id,
                                  -1);

  return action_id;
}

/**
 * polkit_authorization_claim_get_attributes:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 *
 * Gets the attributes for @authorization_claim.
 *
 * Returns: A #GHashTable owned by @authorization_claim. Do not free or modify.
 **/
GHashTable *
polkit_authorization_claim_get_attributes (PolkitAuthorizationClaim *authorization_claim)
{
  GHashTable *attributes;

  g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
  g_return_val_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (authorization_claim)), AUTHORIZATION_CLAIM_SIGNATURE) == 0, NULL);

  egg_dbus_structure_get_element (EGG_DBUS_STRUCTURE (authorization_claim),
                                  2, &attributes,
                                  -1);

  return attributes;
}

/**
 * polkit_authorization_claim_set_subject:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 * @subject: A #PolkitSubject.
 *
 * Sets the subject of @authorization_claim to @subject.
 **/
void
polkit_authorization_claim_set_subject (PolkitAuthorizationClaim *authorization_claim,
                                        PolkitSubject            *subject)
{
  g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim));
  g_return_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (authorization_claim)), AUTHORIZATION_CLAIM_SIGNATURE) == 0);

  egg_dbus_structure_set_element (EGG_DBUS_STRUCTURE (authorization_claim),
                                  0, subject,
                                  -1);
}

/**
 * polkit_authorization_claim_set_action_id:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 * @action_id: The action identifier for the PolicyKit action the claim is about.
 *
 * Sets the PolicyKit action for @authorization_claim to @action_id.
 **/
void
polkit_authorization_claim_set_action_id (PolkitAuthorizationClaim *authorization_claim,
                                          const gchar              *action_id)
{
  g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim));
  g_return_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (authorization_claim)), AUTHORIZATION_CLAIM_SIGNATURE) == 0);
  g_return_if_fail (action_id != NULL);

  egg_dbus_structure_set_element (EGG_DBUS_STRUCTURE (authorization_claim),
                                  1, action_id,
                                  -1);
}

/**
 * polkit_authorization_claim_set_attribute:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 * @key: Key of the attribute.
 * @value: Value of the attribute or %NULL to clear the attribute for @key.
 *
 * Sets or clear an attribute of @authorization_claim.
 **/
void
polkit_authorization_claim_set_attribute (PolkitAuthorizationClaim *authorization_claim,
                                          const gchar              *key,
                                          const gchar              *value)
{
  EggDBusHashTable *attributes;

  g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim));
  g_return_if_fail (strcmp (egg_dbus_structure_get_signature (EGG_DBUS_STRUCTURE (authorization_claim)), AUTHORIZATION_CLAIM_SIGNATURE) == 0);
  g_return_if_fail (key != NULL);

  attributes = polkit_authorization_claim_get_attributes (authorization_claim);

  if (value == NULL)
    g_hash_table_remove (attributes, key);
  else
    g_hash_table_insert (attributes, g_strdup (key), g_strdup (value));
}


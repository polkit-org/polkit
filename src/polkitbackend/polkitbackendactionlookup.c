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
#include <string.h>

#define _POLKIT_BACKEND_ACTION_LOOKUP_NO_DEPRECATED_WARNING

#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>
#include "polkitbackendactionlookup.h"

#include "polkitbackendprivate.h"

/**
 * SECTION:polkitbackendactionlookup
 * @title: PolkitBackendActionLookup
 * @short_description: Interface used to provide data to authentication dialogs
 * @stability: Unstable
 *
 * An interface that is used by backends to provide localized data
 * shown in authentication dialogs.
 *
 * This inteface is intended for mechanisms to customize the message
 * to show - a mechanism can provide a #GIOModule that registers one
 * or more extensions that implement this interface. Every time an
 * authentication dialog is shown, the registered extensions are
 * consulted in priority order.
 *
 * This is useful if your mechanism wants to put up a message such as
 * "Authentication is required to install 'Totem Movie Player'",
 * e.g. messages that include more information than just the action
 * name.
 *
 * Code implementing this interface <emphasis>cannot</emphasis> block
 * or do any IO when methods are invoked. If information is needed to
 * format the message or details, prepare it in advance and pass it as
 * part of the @details object when doing the
 * polkit_authority_check_authorization() call. Then the code in this
 * interface can use that information to return localized data.
 *
 * Note that setlocale() and the <literal>LANG</literal> environment
 * variable will be set up to match the locale of the authentication
 * agent that is the receiver of the information. This means that code
 * implementing this interface can use dgettext() or similar machinery
 * to look up translations.
 */

static void
base_init (gpointer g_iface)
{
}

GType
polkit_backend_action_lookup_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;

  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      static const GTypeInfo info =
      {
        sizeof (PolkitBackendActionLookupIface),
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
        g_type_register_static (G_TYPE_INTERFACE, "PolkitBackendActionLookup", &info, 0);

      g_type_interface_add_prerequisite (iface_type, G_TYPE_OBJECT);
      g_once_init_leave (&g_define_type_id__volatile, iface_type);
    }

  return g_define_type_id__volatile;
}

/**
 * polkit_backend_action_lookup_get_message:
 * @lookup: A #PolkitBackendActionLookup.
 * @action_id: The action to get the message for.
 * @details: Details passed to polkit_authority_check_authorization().
 * @action_description: A #PolkitActionDescription object for @action_id.
 *
 * Computes a message to show in an authentication dialog for
 * @action_id and @details.
 *
 * Returns: A localized string to show in the authentication dialog or %NULL. Caller must free this string.
 **/
gchar *
polkit_backend_action_lookup_get_message (PolkitBackendActionLookup *lookup,
                                          const gchar               *action_id,
                                          PolkitDetails             *details,
                                          PolkitActionDescription   *action_description)
{
  PolkitBackendActionLookupIface *iface = POLKIT_BACKEND_ACTION_LOOKUP_GET_IFACE (lookup);

  if (iface->get_message == NULL)
    return NULL;
  else
    return iface->get_message (lookup, action_id, details, action_description);
}

/**
 * polkit_backend_action_lookup_get_icon_name:
 * @lookup: A #PolkitBackendActionLookup.
 * @action_id: The action to get the themed icon for.
 * @details: Details passed to polkit_authority_check_authorization().
 * @action_description: A #PolkitActionDescription object for @action_id.
 *
 * Computes a themed icon name to show in an authentication dialog for
 * @action_id and @details.
 *
 * Returns: A themed icon name or %NULL. Caller must free this string.
 **/
gchar *
polkit_backend_action_lookup_get_icon_name (PolkitBackendActionLookup *lookup,
                                            const gchar               *action_id,
                                            PolkitDetails             *details,
                                            PolkitActionDescription   *action_description)
{
  PolkitBackendActionLookupIface *iface = POLKIT_BACKEND_ACTION_LOOKUP_GET_IFACE (lookup);

  if (iface->get_icon_name == NULL)
    return NULL;
  else
    return iface->get_icon_name (lookup, action_id, details, action_description);
}

/**
 * polkit_backend_action_lookup_get_details:
 * @lookup: A #PolkitBackendActionLookup.
 * @action_id: The action to get the details for.
 * @details: Details passed to polkit_authority_check_authorization().
 * @action_description: A #PolkitActionDescription object for @action_id.
 *
 * Computes localized details to show in an authentication dialog for
 * @action_id and @details.
 *
 * Returns: A #PolkitDetails object with localized details or %NULL. Caller must free the result.
 **/
PolkitDetails *
polkit_backend_action_lookup_get_details (PolkitBackendActionLookup *lookup,
                                          const gchar               *action_id,
                                          PolkitDetails             *details,
                                          PolkitActionDescription   *action_description)
{
  PolkitBackendActionLookupIface *iface = POLKIT_BACKEND_ACTION_LOOKUP_GET_IFACE (lookup);

  if (iface->get_details == NULL)
    return NULL;
  else
    return iface->get_details (lookup, action_id, details, action_description);
}


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

#ifndef __POLKIT_ACTION_DESCRIPTION_H
#define __POLKIT_ACTION_DESCRIPTION_H

#include <sys/types.h>
#include <unistd.h>
#include <glib-object.h>
#include <polkit/polkitbindings.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_ACTION_DESCRIPTION         (polkit_action_description_get_type())
#define POLKIT_ACTION_DESCRIPTION(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_ACTION_DESCRIPTION, PolkitActionDescription))
#define POLKIT_IS_ACTION_DESCRIPTION(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_ACTION_DESCRIPTION))
#define POLKIT_ACTION_DESCRIPTION_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE((o), POLKIT_TYPE_ACTION_DESCRIPTION, PolkitActionDescriptionIface))

#if 0
typedef struct _PolkitActionDescription PolkitActionDescription; /* Dummy typedef */
#endif
typedef struct _PolkitActionDescriptionIface PolkitActionDescriptionIface;

struct _PolkitActionDescriptionIface
{
  GTypeInterface g_iface;
};

GType         polkit_action_description_get_type         (void) G_GNUC_CONST;
const gchar  *polkit_action_description_get_action_id    (PolkitActionDescription *action_description);
const gchar  *polkit_action_description_get_description  (PolkitActionDescription *action_description);
const gchar  *polkit_action_description_get_message      (PolkitActionDescription *action_description);
const gchar  *polkit_action_description_get_vendor_name  (PolkitActionDescription *action_description);
const gchar  *polkit_action_description_get_vendor_url   (PolkitActionDescription *action_description);
GIcon        *polkit_action_description_get_icon         (PolkitActionDescription *action_description);
GHashTable   *polkit_action_description_get_annotations  (PolkitActionDescription *action_description);

G_END_DECLS

#endif /* __POLKIT_ACTION_DESCRIPTION_H */

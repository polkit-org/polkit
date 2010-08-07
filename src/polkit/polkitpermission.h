/*
 * Copyright (C) 2008-2010 Red Hat, Inc.
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
 * Author: Matthias Clasen <mclasen@redhat.com>
 *         David Zeuthen <davidz@redhat.com>
 */

#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_PERMISSION_H
#define __POLKIT_PERMISSION_H

#include <polkit/polkittypes.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_PERMISSION      (polkit_permission_get_type ())
#define POLKIT_PERMISSION(o)        (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_PERMISSION, PolkitPermission))
#define POLKIT_IS_PERMISSION(o)     (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_PERMISSION))

GType        polkit_permission_get_type        (void) G_GNUC_CONST;
void         polkit_permission_new             (const gchar         *action_id,
                                                PolkitSubject       *subject,
                                                GCancellable        *cancellable,
                                                GAsyncReadyCallback  callback,
                                                gpointer             user_data);
GPermission *polkit_permission_new_finish      (GAsyncResult        *res,
                                                GError             **error);
GPermission *polkit_permission_new_sync        (const gchar         *action_id,
                                                PolkitSubject       *subject,
                                                GCancellable        *cancellable,
                                                GError             **error);
const gchar   *polkit_permission_get_action_id (PolkitPermission    *permission);
PolkitSubject *polkit_permission_get_subject   (PolkitPermission    *permission);

G_END_DECLS

#endif /* __POLKIT_PERMISSION_H */

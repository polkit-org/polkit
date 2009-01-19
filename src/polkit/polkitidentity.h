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

#ifndef __POLKIT_IDENTITY_H
#define __POLKIT_IDENTITY_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkit/polkittypes.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_IDENTITY         (polkit_identity_get_type())
#define POLKIT_IDENTITY(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_IDENTITY, PolkitIdentity))
#define POLKIT_IS_IDENTITY(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_IDENTITY))
#define POLKIT_IDENTITY_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE((o), POLKIT_TYPE_IDENTITY, PolkitIdentityIface))

#if 0
typedef struct _PolkitIdentity PolkitIdentity; /* Dummy typedef */
#endif
typedef struct _PolkitIdentityIface PolkitIdentityIface;

struct _PolkitIdentityIface
{
  GTypeInterface parent_iface;

  gboolean (*equal)     (PolkitIdentity *a,
                         PolkitIdentity *b);

  gchar *  (*to_string) (PolkitIdentity *identity);
};

GType          polkit_identity_get_type      (void) G_GNUC_CONST;
gboolean       polkit_identity_equal         (PolkitIdentity *a,
                                              PolkitIdentity *b);
gchar          *polkit_identity_to_string    (PolkitIdentity *identity);
PolkitIdentity *polkit_identity_from_string  (const gchar   *str,
                                              GError       **error);

G_END_DECLS

#endif /* __POLKIT_IDENTITY_H */

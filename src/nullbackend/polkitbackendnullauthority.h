/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifndef __POLKIT_BACKEND_NULL_AUTHORITY_H
#define __POLKIT_BACKEND_NULL_AUTHORITY_H

#include <polkitbackend/polkitbackend.h>

G_BEGIN_DECLS

#define POLKIT_BACKEND_TYPE_NULL_AUTHORITY         (polkit_backend_null_authority_get_type ())
#define POLKIT_BACKEND_NULL_AUTHORITY(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_BACKEND_TYPE_NULL_AUTHORITY, PolkitBackendNullAuthority))
#define POLKIT_BACKEND_NULL_AUTHORITY_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_BACKEND_TYPE_NULL_AUTHORITY, PolkitBackendNullAuthorityClass))
#define POLKIT_BACKEND_NULL_AUTHORITY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_BACKEND_TYPE_NULL_AUTHORITY,PolkitBackendNullAuthorityClass))
#define POLKIT_BACKEND_IS_NULL_AUTHORITY(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_BACKEND_TYPE_NULL_AUTHORITY))
#define POLKIT_BACKEND_IS_NULL_AUTHORITY_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_BACKEND_TYPE_NULL_AUTHORITY))

typedef struct _PolkitBackendNullAuthority PolkitBackendNullAuthority;
typedef struct _PolkitBackendNullAuthorityClass PolkitBackendNullAuthorityClass;
typedef struct _PolkitBackendNullAuthorityPrivate PolkitBackendNullAuthorityPrivate;

struct _PolkitBackendNullAuthority
{
  PolkitBackendAuthority parent_instance;
  PolkitBackendNullAuthorityPrivate *priv;
};

struct _PolkitBackendNullAuthorityClass
{
  PolkitBackendAuthorityClass parent_class;

};

GType  polkit_backend_null_authority_get_type (void) G_GNUC_CONST;

void   polkit_backend_null_authority_register (GIOModule *module);

G_END_DECLS

#endif /* __POLKIT_BACKEND_NULL_AUTHORITY_H */


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

#if !defined(_POLKIT_LOCAL_INSIDE_POLKIT_LOCAL_H) && !defined (_POLKIT_LOCAL_COMPILATION)
#error "Only <polkitlocal/polkitlocal.h> can be included directly, this file may disappear or change contents"
#endif

#ifndef __POLKIT_LOCAL_TYPES_H
#define __POLKIT_LOCAL_TYPES_H

#include <polkit/polkit.h>

G_BEGIN_DECLS

struct _PolkitLocalAuthority;
typedef struct _PolkitLocalAuthority PolkitLocalAuthority;

struct _PolkitLocalAuthorization;
typedef struct _PolkitLocalAuthorization PolkitLocalAuthorization;

G_END_DECLS

#endif /* __POLKIT_LOCAL_TYPES_H */

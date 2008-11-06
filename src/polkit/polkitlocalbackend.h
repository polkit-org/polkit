/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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

#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_LOCAL_BACKEND_H
#define __POLKIT_LOCAL_BACKEND_H

#include <polkit/polkitbackend.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_LOCAL_BACKEND         (polkit_local_backend_get_type ())
#define POLKIT_LOCAL_BACKEND(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_LOCAL_BACKEND, PolkitLocalBackend))
#define POLKIT_LOCAL_BACKEND_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_TYPE_LOCAL_BACKEND, PolkitLocalBackendClass))
#define POLKIT_LOCAL_BACKEND_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_LOCAL_BACKEND,PolkitLocalBackendClass))
#define POLKIT_IS_LOCAL_BACKEND(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_LOCAL_BACKEND))
#define POLKIT_IS_LOCAL_BACKEND_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_LOCAL_BACKEND))

typedef struct _PolkitLocalBackend        PolkitLocalBackend;
typedef struct _PolkitLocalBackendClass   PolkitLocalBackendClass;
typedef struct _PolkitLocalBackendPrivate PolkitLocalBackendPrivate;

struct _PolkitLocalBackend
{
        PolkitBackend              parent_instance;

        /*< private >*/
        PolkitLocalBackendPrivate *priv;
};

struct _PolkitLocalBackendClass
{
        PolkitBackendClass parent_class;
};

GType           polkit_local_backend_get_type  (void) G_GNUC_CONST;
PolkitBackend  *polkit_local_backend_new       (void);

G_END_DECLS

#endif /* __POLKIT_LOCAL_BACKEND_H */


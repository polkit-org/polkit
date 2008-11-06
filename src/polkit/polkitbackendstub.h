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

#ifndef __POLKIT_BACKEND_STUB_H__
#define __POLKIT_BACKEND_STUB_H__

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <polkit/polkitbackend.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_BACKEND_STUB         (polkit_backend_stub_get_type ())
#define POLKIT_BACKEND_STUB(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_BACKEND_STUB, PolkitBackendStub))
#define POLKIT_BACKEND_STUB_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_BACKEND_STUB, PolkitBackendStubClass))
#define POLKIT_IS_BACKEND_STUB(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_BACKEND_STUB))
#define POLKIT_IS_BACKEND_STUB_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_BACKEND_STUB))
#define POLKIT_BACKEND_STUB_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_BACKEND_STUB, PolkitBackendStubClass))

typedef struct _PolkitBackendStub        PolkitBackendStub;
typedef struct _PolkitBackendStubClass   PolkitBackendStubClass;
typedef struct _PolkitBackendStubPrivate PolkitBackendStubPrivate;

struct _PolkitBackendStub
{
        GObject                   parent_instance;
        PolkitBackendStubPrivate *priv;
};

struct _PolkitBackendStubClass
{
        GObjectClass parent_class;
};

GType               polkit_backend_stub_get_type (void) G_GNUC_CONST;
PolkitBackendStub  *polkit_backend_stub_new      (DBusGConnection   *connection,
                                                  const char        *object_path,
                                                  PolkitBackend     *backend);

G_END_DECLS

#endif /* __POLKIT_BACKEND_STUB_H__ */

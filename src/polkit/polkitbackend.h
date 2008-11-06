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

#ifndef __POLKIT_BACKEND_H
#define __POLKIT_BACKEND_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkit/polkitauthorizationclaim.h>
#include <polkit/polkitauthorizationresult.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_BACKEND         (polkit_backend_get_type ())
#define POLKIT_BACKEND(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_BACKEND, PolkitBackend))
#define POLKIT_BACKEND_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_TYPE_BACKEND, PolkitBackendClass))
#define POLKIT_BACKEND_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_BACKEND,PolkitBackendClass))
#define POLKIT_IS_BACKEND(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_BACKEND))
#define POLKIT_IS_BACKEND_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_BACKEND))

typedef struct _PolkitBackend        PolkitBackend;
typedef struct _PolkitBackendClass   PolkitBackendClass;

struct _PolkitBackend
{
        GObject parent_instance;
};

/* TODO: maybe we also want async versions that are tried before the sync ones */

struct _PolkitBackendClass
{
        GObjectClass parent_class;

        /*< public >*/

        /* signals */
        void   (* changed)           (PolkitBackend     *backend);

        /* vtable */
        gchar * (* say_hello)   (PolkitBackend       *backend,
                                 PolkitSubject       *inquirer,
                                 const gchar         *name,
                                 GError             **error);

        PolkitAuthorizationResult  (* check_claims) (PolkitBackend       *backend,
                                                     PolkitSubject       *inquirer,
                                                     GList               *claims,
                                                     GError             **error);

        /*< private >*/

        /* Padding for future expansion */
        void (*_polkit_reserved1) (void);
        void (*_polkit_reserved2) (void);
        void (*_polkit_reserved3) (void);
        void (*_polkit_reserved4) (void);
        void (*_polkit_reserved5) (void);
        void (*_polkit_reserved6) (void);
        void (*_polkit_reserved7) (void);
        void (*_polkit_reserved8) (void);
};

GType  polkit_backend_get_type         (void) G_GNUC_CONST;

gchar *polkit_backend_say_hello        (PolkitBackend        *backend,
                                        PolkitSubject        *inquirer,
                                        const gchar          *name,
                                        GError              **error);

PolkitAuthorizationResult  polkit_backend_check_claims (PolkitBackend       *backend,
                                                        PolkitSubject       *inquirer,
                                                        GList               *claims,
                                                        GError             **error);

G_END_DECLS

#endif /* __POLKIT_BACKEND_H */


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

#include "config.h"
#include "polkitbackend.h"

/**
 * SECTION:polkitbackend
 * @short_description: Abstract base class for backends
 * @include: polkit/polkit.h
 *
 * The #PolkitBackend class represents a backend responding to
 * requests from instances of the #PolkitAuthority class.
 */

G_DEFINE_ABSTRACT_TYPE (PolkitBackend, polkit_backend, G_TYPE_OBJECT);

enum {
        CHANGED_SIGNAL,
        LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
polkit_backend_finalize (GObject *object)
{
        PolkitBackend *backend;

        backend = POLKIT_BACKEND (object);

        G_OBJECT_CLASS (polkit_backend_parent_class)->finalize (object);
}

static void
polkit_backend_class_init (PolkitBackendClass *klass)
{
        GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

        gobject_class->finalize = polkit_backend_finalize;

        /**
         * PolkitBackend::changed:
         * @backend: a #PolkitBackend.
         *
         * Emitted when something on @backend changes.
         */
        signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                                POLKIT_TYPE_BACKEND,
                                                G_SIGNAL_RUN_LAST,
                                                G_STRUCT_OFFSET (PolkitBackendClass, changed),
                                                NULL,
                                                NULL,
                                                g_cclosure_marshal_VOID__VOID,
                                                G_TYPE_NONE,
                                                0);
}

static void
polkit_backend_init (PolkitBackend *backend)
{
}

gchar *
polkit_backend_say_hello (PolkitBackend        *backend,
                          PolkitSubject        *inquirer,
                          const gchar          *name,
                          GError              **error)
{
        PolkitBackendClass *klass;

        g_return_val_if_fail (POLKIT_IS_BACKEND (backend), NULL);
        klass = POLKIT_BACKEND_GET_CLASS (backend);

        return (* klass->say_hello) (backend,
                                     inquirer,
                                     name,
                                     error);
}

PolkitAuthorizationResult
polkit_backend_check_claims (PolkitBackend       *backend,
                             PolkitSubject       *inquirer,
                             GList               *claims,
                             GError             **error)
{
        PolkitBackendClass *klass;

        g_return_val_if_fail (POLKIT_IS_BACKEND (backend), POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED);
        klass = POLKIT_BACKEND_GET_CLASS (backend);

        return (* klass->check_claims) (backend,
                                        inquirer,
                                        claims,
                                        error);
}


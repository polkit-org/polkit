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
#include "polkitauthoritystub.h"

/* TODO: locking */

static PolkitAuthority *the_authority = NULL;

/**
 * polkit_authority_get:
 *
 * Gets the default authority for checking claims.
 *
 * Returns: A reference to a #PolkitAuthority instance. Call g_object_unref() when done with it
 **/
PolkitAuthority *
polkit_authority_get (void)
{
        PolkitAuthority *authority;

        polkit_bindings_register_types (); /* TODO: use __attribute ((constructor)) */

        if (the_authority != NULL) {
                authority = g_object_ref (the_authority);
        } else {
                EggDBusConnection *connection;

                connection = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);
                authority = POLKIT_AUTHORITY (egg_dbus_connection_get_proxy (connection,
                                                                             "org.freedesktop.PolicyKit1",
                                                                             "/org/freedesktop/PolicyKit1/Authority"));

                /* TODO: take a weak reference and set the_authority to NULL on destruction */

                /* TODO: unref connection since authority holds a reference? */
        }

        return authority;
}

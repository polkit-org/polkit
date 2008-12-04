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
#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <polkit/polkit.h>
#include "polkitbackendlocal.h"

/* TODO: locking */

typedef struct
{
        guint foo;
} PolkitBackendLocalPrivate;

static void authority_iface_init (PolkitAuthorityIface *authority_iface,
                                  gpointer              iface_data);

G_DEFINE_TYPE_WITH_CODE (PolkitBackendLocal, polkit_backend_local, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_AUTHORITY,
                                                authority_iface_init)
                         );

#define POLKIT_BACKEND_LOCAL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_BACKEND_LOCAL, PolkitBackendLocalPrivate))

static void
polkit_backend_local_finalize (GObject *object)
{
        PolkitBackendLocal *backend;
        PolkitBackendLocalPrivate *priv;

        backend = POLKIT_BACKEND_LOCAL (object);
        priv = POLKIT_BACKEND_LOCAL_GET_PRIVATE (backend);

        G_OBJECT_CLASS (polkit_backend_local_parent_class)->finalize (object);
}

static void
polkit_backend_local_class_init (PolkitBackendLocalClass *klass)
{
        GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

        gobject_class->finalize = polkit_backend_local_finalize;

        g_type_class_add_private (klass, sizeof (PolkitBackendLocalPrivate));
}


static void
polkit_backend_local_init (PolkitBackendLocal *backend)
{
        PolkitBackendLocalPrivate *priv;

        priv = POLKIT_BACKEND_LOCAL_GET_PRIVATE (backend);
}

PolkitBackendLocal *
polkit_backend_local_new (void)
{
        PolkitBackendLocal *backend;

        backend = POLKIT_BACKEND_LOCAL (g_object_new (POLKIT_TYPE_BACKEND_LOCAL,
                                                      NULL));

        return backend;
}

static void
authority_iface_handle_say_hello (PolkitAuthority *instance,
                                  const gchar *message,
                                  EggDBusMethodInvocation *method_invocation)
{
        gchar *result;

        result = g_strdup_printf ("You said '%s' to the AUTHORITY!", message);

        polkit_authority_handle_say_hello_finish (method_invocation,
                                                  result);

        g_free (result);
}

static void
authority_iface_handle_enumerate_users (PolkitAuthority *instance,
                                        EggDBusMethodInvocation *method_invocation)
{
        struct passwd *passwd;
        GList *list;

        list = NULL;

        passwd = getpwent ();
        if (passwd == NULL) {
                egg_dbus_method_invocation_return_error (method_invocation,
                                                         POLKIT_ERROR,
                                                         POLKIT_ERROR_FAILED,
                                                         "getpwent failed: %s",
                                                         strerror (errno));
                goto out;
        }

        do {
                PolkitSubject *subject;

                subject = polkit_subject_new_for_unix_user (passwd->pw_uid);

                list = g_list_prepend (list, subject);
        } while ((passwd = getpwent ()) != NULL);
        endpwent ();

        list = g_list_reverse (list);

        polkit_authority_handle_enumerate_users_finish (method_invocation,
                                                        list);

 out:
        g_list_foreach (list, (GFunc) g_object_unref, NULL);
        g_list_free (list);
}

static void
authority_iface_init (PolkitAuthorityIface *authority_iface,
                      gpointer              iface_data)
{
        authority_iface->handle_say_hello        = authority_iface_handle_say_hello;
        authority_iface->handle_enumerate_users  = authority_iface_handle_enumerate_users;
}

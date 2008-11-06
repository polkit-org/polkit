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
#include <glib.h>
#include <glib/gi18n-lib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "polkiterror.h"
#include "polkitbackendstub.h"
#include "polkituser.h"
#include "polkitserialization.h"

/**
 * SECTION:polkitbackendstub
 * @short_description: Stub for proxying backends
 * @include: polkit/polkit.h
 *
 * Used on the server side for proxying a #PolkitBackend over
 * D-Bus. On the client side, #PolkitAuthority is used.
 */

/*--------------------------------------------------------------------------------------------------------------*/

/* exported methods */

gboolean _polkit_backend_stub_say_hello (PolkitBackendStub     *backend_stub,
                                         const char             *name,
                                         DBusGMethodInvocation  *context);

gboolean _polkit_backend_stub_check_claims (PolkitBackendStub     *backend_stub,
                                            GPtrArray              *_claims,
                                            DBusGMethodInvocation  *context);

#include "polkitbackendstubglue.h"

/*--------------------------------------------------------------------------------------------------------------*/

struct _PolkitBackendStubPrivate
{
        PolkitBackend *backend;
};

G_DEFINE_TYPE (PolkitBackendStub, polkit_backend_stub, G_TYPE_OBJECT)

#define POLKIT_BACKEND_STUB_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_BACKEND_STUB, PolkitBackendStubPrivate))

static void
polkit_backend_stub_init (PolkitBackendStub *backend_stub)
{
        backend_stub->priv = POLKIT_BACKEND_STUB_GET_PRIVATE (backend_stub);

}

static void
polkit_backend_stub_finalize (GObject *object)
{
        PolkitBackendStub *backend_stub;

        g_return_if_fail (object != NULL);
        g_return_if_fail (POLKIT_IS_BACKEND_STUB (object));

        backend_stub = POLKIT_BACKEND_STUB (object);

        if (backend_stub->priv->backend != NULL)
                g_object_unref (backend_stub->priv->backend);

        G_OBJECT_CLASS (polkit_backend_stub_parent_class)->finalize (object);
}

static void
polkit_backend_stub_class_init (PolkitBackendStubClass *klass)
{
        GObjectClass   *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = polkit_backend_stub_finalize;

        g_type_class_add_private (klass, sizeof (PolkitBackendStubPrivate));

        dbus_g_error_domain_register (POLKIT_ERROR,
                                      "org.freedesktop.PolicyKit.Error",
                                      POLKIT_TYPE_ERROR);

        dbus_g_object_type_install_info (POLKIT_TYPE_BACKEND_STUB, &dbus_glib__polkit_backend_stub_object_info);
}

PolkitBackendStub *
polkit_backend_stub_new (DBusGConnection   *connection,
                             const char        *object_path,
                             PolkitBackend  *backend)
{
        PolkitBackendStub *backend_stub;

        backend_stub = POLKIT_BACKEND_STUB (g_object_new (POLKIT_TYPE_BACKEND_STUB, NULL));

        dbus_g_connection_register_g_object (connection,
                                             object_path,
                                             G_OBJECT (backend_stub));

        backend_stub->priv->backend = g_object_ref (backend);

        return backend_stub;
}

/*--------------------------------------------------------------------------------------------------------------*/

static PolkitSubject *
get_inquirer (DBusGMethodInvocation *context)
{
        PolkitSubject *subject;

        /* TODO; get from context */
        subject = polkit_user_new ("root");

        return subject;
}

/*--------------------------------------------------------------------------------------------------------------*/
/* exported methods */

gboolean
_polkit_backend_stub_say_hello (PolkitBackendStub      *backend_stub,
                                const char             *name,
                                DBusGMethodInvocation  *context)
{
        PolkitSubject *inquirer;
        GError *error;
        char *result;

        error = NULL;
        inquirer = get_inquirer (context);

        result = polkit_backend_say_hello (backend_stub->priv->backend,
                                           inquirer,
                                           name,
                                           &error);

        if (error != NULL) {
                dbus_g_method_return_error (context, error);
                g_error_free (error);
        } else {
                dbus_g_method_return (context, result);
                g_free (result);
        }

        g_object_unref (inquirer);

        return TRUE;
}

/*--------------------------------------------------------------------------------------------------------------*/

gboolean
_polkit_backend_stub_check_claims (PolkitBackendStub      *backend_stub,
                                   GPtrArray              *_claims,
                                   DBusGMethodInvocation  *context)
{
        PolkitSubject *inquirer;
        GError *error;
        GList *claims;
        PolkitAuthorizationResult result;

        error = NULL;
        inquirer = get_inquirer (context);

        claims = _serialize_ptr_array_to_obj_list
                (_claims,
                 (PolkitSerializeToObjectFunc) _authorization_claim_from_data);

        if (claims == NULL) {
                dbus_g_method_return_error (context,
                                            g_error_new (POLKIT_ERROR,
                                                         POLKIT_ERROR_FAILED,
                                                         "Data is malformed"));
                goto out;
        }

        result = polkit_backend_check_claims (backend_stub->priv->backend,
                                              inquirer,
                                              claims,
                                              &error);

        if (error != NULL) {
                dbus_g_method_return_error (context, error);
                g_error_free (error);
        } else {
                char *result_str;
                result_str = _authorization_result_to_string (result);
                dbus_g_method_return (context, result_str);
                g_free (result_str);
        }

        g_object_unref (inquirer);

        g_list_foreach (claims, (GFunc) g_object_unref, NULL);
        g_list_free (claims);

 out:
        return TRUE;
}

/*--------------------------------------------------------------------------------------------------------------*/

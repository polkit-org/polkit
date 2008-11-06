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
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "polkitauthority.h"
#include "polkitauthorityglue.h"
#include "polkitserialization.h"

/**
 * SECTION:polkitauthority
 * @short_description: Authorization checking and management
 * @include: polkit/polkit.h
 *
 * The #PolkitAuthority class represents an authority that can check
 * claims made by third parties. Some implementations allow managing
 * authorizations.
 */

struct _PolkitAuthorityPrivate
{
        DBusGProxy *dbus_proxy;
};

G_DEFINE_TYPE (PolkitAuthority, polkit_authority, G_TYPE_OBJECT);

#define POLKIT_AUTHORITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_AUTHORITY, PolkitAuthorityPrivate))

enum {
        CHANGED_SIGNAL,
        LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
polkit_authority_finalize (GObject *object)
{
        PolkitAuthority *authority;

        authority = POLKIT_AUTHORITY (object);

        if (authority->priv->dbus_proxy != NULL)
                g_object_unref (authority->priv->dbus_proxy);

        G_OBJECT_CLASS (polkit_authority_parent_class)->finalize (object);
}

static void
polkit_authority_class_init (PolkitAuthorityClass *klass)
{
        GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

        gobject_class->finalize = polkit_authority_finalize;

        /**
         * PolkitAuthority::changed:
         * @authority: a #PolkitAuthority.
         *
         * Emitted when something on @authority changes.
         */
        signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                                POLKIT_TYPE_AUTHORITY,
                                                G_SIGNAL_RUN_LAST,
                                                G_STRUCT_OFFSET (PolkitAuthorityClass, changed),
                                                NULL,
                                                NULL,
                                                g_cclosure_marshal_VOID__VOID,
                                                G_TYPE_NONE,
                                                0);

        g_type_class_add_private (klass, sizeof (PolkitAuthorityPrivate));
}


static void
polkit_authority_init (PolkitAuthority *authority)
{
        authority->priv = POLKIT_AUTHORITY_GET_PRIVATE (authority);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
say_hello_cb (DBusGProxy *dbus_proxy,
              char        *result,
              GError      *error,
              gpointer     user_data)
{
        GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
        if (error != NULL)
                g_simple_async_result_set_from_error (simple, error);
        else
                g_simple_async_result_set_op_res_gpointer (simple, result, NULL);
        g_simple_async_result_complete (simple);
}

void
polkit_authority_say_hello (PolkitAuthority    *authority,
                            const gchar          *name,
                            GCancellable         *cancellable,
                            GAsyncReadyCallback   callback,
                            gpointer              user_data)
{
        GSimpleAsyncResult *simple;

        simple = g_simple_async_result_new (G_OBJECT (authority),
                                            callback,
                                            user_data,
                                            polkit_authority_say_hello);

        org_freedesktop_PolicyKit1_Authority_say_hello_async (authority->priv->dbus_proxy,
                                                              name,
                                                              say_hello_cb,
                                                              simple);
}

gchar *
polkit_authority_say_hello_finish (PolkitAuthority    *authority,
                                     GAsyncResult        *res,
                                     GError             **error)
{
        GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);
        g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_say_hello);
        g_simple_async_result_propagate_error (simple, error);
        return g_simple_async_result_get_op_res_gpointer (simple);
}

/**
 * polkit_authority_say_hello_sync:
 * @authority: A #PolkitAuthority.
 * @name: A name to say hello to.
 * @cancellable: A #GCancellable or %NULL.
 * @error: Return location for error.
 *
 * Says hello to @name.
 *
 * Returns: %NULL if @error is set, otherwise a newly allocated string
 * containing the greeting, free with g_free().
 **/
gchar *
polkit_authority_say_hello_sync (PolkitAuthority *authority,
                                 const gchar      *name,
                                 GCancellable     *cancellable,
                                 GError          **error)
{
        gchar *result;

        if (org_freedesktop_PolicyKit1_Authority_say_hello (authority->priv->dbus_proxy,
                                                            name,
                                                            &result,
                                                            error)) {
                return result;
        } else {
                return NULL;
        }
}

/* ---------------------------------------------------------------------------------------------------- */

PolkitAuthorizationResult
polkit_authority_check_claims_sync (PolkitAuthority     *authority,
                                    GList               *claims,
                                    GCancellable        *cancellable,
                                    GError             **error)
{
        PolkitAuthorizationResult result;
        char *result_str;
        GPtrArray *p;

        result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

        p = _serialize_ptr_array_from_obj_list
                (claims,
                 (PolkitSerializeFromObjectFunc) _authorization_claim_to_value);

        if (org_freedesktop_PolicyKit1_Authority_check_claims (authority->priv->dbus_proxy,
                                                               p,
                                                               &result_str,
                                                               error)) {
                result = _authorization_result_from_string (result_str);
        }

        _free_serialized_obj_ptr_array (p);

        return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitAuthority *
_polkit_authority_new (DBusGConnection  *connection,
                       const gchar      *service_name,
                       const gchar      *object_path)
{
        PolkitAuthority *authority;

        authority = POLKIT_AUTHORITY (g_object_new (POLKIT_TYPE_AUTHORITY, NULL));
        authority->priv->dbus_proxy = dbus_g_proxy_new_for_name (connection,
                                                                 service_name,
                                                                 object_path,
                                                                 "org.freedesktop.PolicyKit1.Authority");

        return authority;
}

/**
 * polkit_authority_get:
 *
 * Gets the default authority for checking claims.
 *
 * Returns: A reference to a #PolkitAuthority instance. Call
 * g_object_unref() to free it.
 **/
PolkitAuthority *
polkit_authority_get (void)
{
        PolkitAuthority *authority;
        DBusGConnection *bus;
        GError *error;

        bus = NULL;
        authority = NULL;

        error = NULL;
        bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
        if (bus == NULL) {
                g_warning ("Couldn't connect to system bus: %s", error->message);
                g_error_free (error);
                goto out;
        }

        authority = _polkit_authority_new (bus,
                                          "org.freedesktop.PolicyKit1",
                                          "/authority");

 out:
        if (bus != NULL)
                dbus_g_connection_unref (bus);
        return authority;
}

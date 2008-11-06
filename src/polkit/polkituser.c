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
#include <string.h>

#include "polkituser.h"

/**
 * SECTION:polkituser
 * @short_description: User
 * @include: polkit/polkit.h
 *
 * Represents a user.
 */

/*--------------------------------------------------------------------------------------------------------------*/

struct _PolkitUserPrivate
{
        char *user_name;
};

enum {
        PROP_0,
        PROP_USER_NAME,
};

static void polkit_user_subject_iface_init (PolkitSubjectIface *iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUser, polkit_user, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT,
                                                polkit_user_subject_iface_init))

#define POLKIT_USER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_USER, PolkitUserPrivate))

static void
polkit_user_get_property (GObject    *object,
                          guint       prop_id,
                          GValue     *value,
                          GParamSpec *pspec)
{
        PolkitUser *user = POLKIT_USER (object);

        switch (prop_id) {
        case PROP_USER_NAME:
                g_value_set_string (value, user->priv->user_name);
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
polkit_user_set_property (GObject      *object,
                          guint         prop_id,
                          const GValue *value,
                          GParamSpec   *pspec)
{
        PolkitUser *user = POLKIT_USER (object);

        switch (prop_id) {
        case PROP_USER_NAME:
                polkit_user_set_user_name (user, g_value_get_string (value));
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
polkit_user_init (PolkitUser *user)
{
        user->priv = POLKIT_USER_GET_PRIVATE (user);
}

static void
polkit_user_finalize (GObject *object)
{
        PolkitUser *user;

        g_return_if_fail (object != NULL);
        g_return_if_fail (POLKIT_IS_USER (object));

        user = POLKIT_USER (object);

        g_free (user->priv->user_name);

        G_OBJECT_CLASS (polkit_user_parent_class)->finalize (object);
}

static void
polkit_user_class_init (PolkitUserClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->get_property = polkit_user_get_property;
        object_class->set_property = polkit_user_set_property;
        object_class->finalize = polkit_user_finalize;

        /**
         * PolkitUser:user-name:
         *
         * The user name.
         */
        g_object_class_install_property (object_class,
                                         PROP_USER_NAME,
                                         g_param_spec_string ("user-name",
                                                              "user-name",
                                                              "The user name",
                                                              NULL,
                                                              G_PARAM_CONSTRUCT |
                                                              G_PARAM_READWRITE |
                                                              G_PARAM_STATIC_NAME |
                                                              G_PARAM_STATIC_NICK |
                                                              G_PARAM_STATIC_BLURB));

        g_type_class_add_private (klass, sizeof (PolkitUserPrivate));
}

gchar *
polkit_user_get_user_name (PolkitUser *user)
{
        g_return_val_if_fail (POLKIT_IS_USER (user), NULL);
        return g_strdup (user->priv->user_name);
}

void
polkit_user_set_user_name (PolkitUser *user,
                           const char  *user_name)
{
        g_return_if_fail (POLKIT_IS_USER (user));
        g_return_if_fail (user_name != NULL);

        if (user->priv->user_name == NULL || strcmp (user_name, user->priv->user_name) != 0) {
                g_free (user->priv->user_name);
                user->priv->user_name = g_strdup (user_name);
                g_object_notify (G_OBJECT (user), "user-name");
        }
}

PolkitSubject *
polkit_user_new (const gchar *user_name)
{
        return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_USER,
                                             "user-name", user_name,
                                             NULL));
}

static gboolean
polkit_user_equal (PolkitSubject *subject1,
                   PolkitSubject *subject2)
{
        PolkitUser *user1 = POLKIT_USER (subject1);
        PolkitUser *user2 = POLKIT_USER (subject2);

        return strcmp (user1->priv->user_name, user2->priv->user_name) == 0;
}

static void
polkit_user_subject_iface_init (PolkitSubjectIface *iface)
{
        iface->equal = polkit_user_equal;
}

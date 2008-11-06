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
#include "polkitauthorizationclaim.h"

/**
 * SECTION:polkitauthorizationclaim
 * @short_description: Authorization Claim
 * @include: polkit/polkit.h
 *
 * Represents an authorization claim.
 */

/*--------------------------------------------------------------------------------------------------------------*/

struct _PolkitAuthorizationClaimPrivate
{
        PolkitSubject *subject;
        char *action_id;
        GHashTable *attributes;
};

enum {
        PROP_0,
        PROP_SUBJECT,
        PROP_ACTION_ID,
        PROP_ATTRIBUTES,
};


G_DEFINE_TYPE (PolkitAuthorizationClaim, polkit_authorization_claim, G_TYPE_OBJECT)

#define POLKIT_AUTHORIZATION_CLAIM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_AUTHORIZATION_CLAIM, PolkitAuthorizationClaimPrivate))

static void
polkit_authorization_claim_get_property (GObject    *object,
                                         guint       prop_id,
                                         GValue     *value,
                                         GParamSpec *pspec)
{
        PolkitAuthorizationClaim *authorization_claim = POLKIT_AUTHORIZATION_CLAIM (object);

        switch (prop_id) {
        case PROP_SUBJECT:
                g_value_set_object (value, authorization_claim->priv->subject);
                break;

        case PROP_ACTION_ID:
                g_value_set_string (value, authorization_claim->priv->action_id);
                break;

        case PROP_ATTRIBUTES:
                g_value_set_boxed (value, authorization_claim->priv->attributes);
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
polkit_authorization_claim_set_property (GObject      *object,
                                         guint         prop_id,
                                         const GValue *value,
                                         GParamSpec   *pspec)
{
        PolkitAuthorizationClaim *authorization_claim = POLKIT_AUTHORIZATION_CLAIM (object);

        switch (prop_id) {
        case PROP_SUBJECT:
                polkit_authorization_claim_set_subject (authorization_claim, POLKIT_SUBJECT (g_value_get_object (value)));
                break;

        case PROP_ACTION_ID:
                polkit_authorization_claim_set_action_id (authorization_claim, g_value_get_string (value));
                break;

        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
polkit_authorization_claim_init (PolkitAuthorizationClaim *authorization_claim)
{
        authorization_claim->priv = POLKIT_AUTHORIZATION_CLAIM_GET_PRIVATE (authorization_claim);

        authorization_claim->priv->attributes = g_hash_table_new_full (g_str_hash,
                                                                       g_str_equal,
                                                                       g_free,
                                                                       g_free);
}

static void
polkit_authorization_claim_finalize (GObject *object)
{
        PolkitAuthorizationClaim *authorization_claim;

        g_return_if_fail (object != NULL);
        g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (object));

        authorization_claim = POLKIT_AUTHORIZATION_CLAIM (object);

        if (authorization_claim->priv->subject != NULL)
                g_object_unref (authorization_claim->priv->subject);
        g_free (authorization_claim->priv->action_id);
        g_hash_table_unref (authorization_claim->priv->attributes);

        G_OBJECT_CLASS (polkit_authorization_claim_parent_class)->finalize (object);
}

static void
polkit_authorization_claim_class_init (PolkitAuthorizationClaimClass *klass)
{
        GObjectClass   *object_class = G_OBJECT_CLASS (klass);

        object_class->get_property = polkit_authorization_claim_get_property;
        object_class->set_property = polkit_authorization_claim_set_property;
        object_class->finalize = polkit_authorization_claim_finalize;

        /**
         * PolkitAuthorizationClaim:subject:
         *
         * The subject making the authorization claim.
         */
        g_object_class_install_property (object_class,
                                         PROP_SUBJECT,
                                         g_param_spec_object ("subject",
                                                              "subject",
                                                              "The subject making the authorization claim",
                                                              POLKIT_TYPE_SUBJECT,
                                                              G_PARAM_CONSTRUCT |
                                                              G_PARAM_READWRITE |
                                                              G_PARAM_STATIC_NAME |
                                                              G_PARAM_STATIC_NICK |
                                                              G_PARAM_STATIC_BLURB));

        /**
         * PolkitAuthorizationClaim:action-id:
         *
         * The action id for the authorization claim.
         */
        g_object_class_install_property (object_class,
                                         PROP_ACTION_ID,
                                         g_param_spec_string ("action-id",
                                                              "action-id",
                                                              "The action for the authorization claim",
                                                              NULL,
                                                              G_PARAM_CONSTRUCT |
                                                              G_PARAM_READWRITE |
                                                              G_PARAM_STATIC_NAME |
                                                              G_PARAM_STATIC_NICK |
                                                              G_PARAM_STATIC_BLURB));

        /**
         * PolkitAuthorizationClaim:attributes:
         *
         * A #GHashTable from strings into the strings containing
         * attributes for the claim.
         */
        g_object_class_install_property (object_class,
                                         PROP_ATTRIBUTES,
                                         g_param_spec_boxed ("attributes",
                                                             "attributes",
                                                             "The attributes for the authorization claim",
                                                             G_TYPE_HASH_TABLE,
                                                             G_PARAM_READABLE |
                                                             G_PARAM_STATIC_NAME |
                                                             G_PARAM_STATIC_NICK |
                                                             G_PARAM_STATIC_BLURB));

        g_type_class_add_private (klass, sizeof (PolkitAuthorizationClaimPrivate));
}

PolkitSubject *
polkit_authorization_claim_get_subject (PolkitAuthorizationClaim *authorization_claim)
{
        g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
        return g_object_ref (authorization_claim->priv->subject);
}

void
polkit_authorization_claim_set_subject (PolkitAuthorizationClaim *authorization_claim,
                                        PolkitSubject            *subject)
{
        g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim));
        g_return_if_fail (POLKIT_IS_SUBJECT (subject));

        if (!polkit_subject_equal (authorization_claim->priv->subject, subject)) {
                if (authorization_claim->priv->subject != NULL)
                        g_object_unref (authorization_claim->priv->subject);
                authorization_claim->priv->subject = g_object_ref (subject);
        }
}

gchar *
polkit_authorization_claim_get_action_id (PolkitAuthorizationClaim *authorization_claim)
{
        g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
        return g_strdup (authorization_claim->priv->action_id);
}

void
polkit_authorization_claim_set_action_id (PolkitAuthorizationClaim *authorization_claim,
                                          const gchar              *action_id)
{
        g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim));
        g_return_if_fail (action_id != NULL);

        if (authorization_claim->priv->action_id == NULL ||
            strcmp (authorization_claim->priv->action_id, action_id) != 0) {
                g_free (authorization_claim->priv->action_id);
                authorization_claim->priv->action_id = g_strdup (action_id);
                g_object_notify (G_OBJECT (authorization_claim), "action-id");
        }
}

/**
 * polkit_authorization_claim_get_attributes:
 * @authorization_claim: A #PolkitAuthorizationClaim.
 *
 * Gets the attributes (a #GHashTable mapping strings to strings) for
 * @authorization_claim.
 *
 * Returns: A #GHashTable. Caller should not free it, it is owned by
 * @authorization_claim.
 **/
GHashTable *
polkit_authorization_claim_get_attributes (PolkitAuthorizationClaim  *authorization_claim)
{
        g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
        return authorization_claim->priv->attributes;
}

char *
polkit_authorization_claim_get_attribute (PolkitAuthorizationClaim  *authorization_claim,
                                          const gchar               *key)
{
        g_return_val_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim), NULL);
        g_return_val_if_fail (key != NULL, NULL);

        return g_strdup (g_hash_table_lookup (authorization_claim->priv->attributes, key));
}

void
polkit_authorization_claim_set_attribute    (PolkitAuthorizationClaim  *authorization_claim,
                                             const gchar               *key,
                                             const gchar               *value)
{
        g_return_if_fail (POLKIT_IS_AUTHORIZATION_CLAIM (authorization_claim));
        g_return_if_fail (key != NULL);

        if (value == NULL) {
                g_hash_table_remove (authorization_claim->priv->attributes, key);
        } else {
                g_hash_table_replace (authorization_claim->priv->attributes,
                                      g_strdup (key),
                                      g_strdup (value));
        }
}


PolkitAuthorizationClaim *
polkit_authorization_claim_new (PolkitSubject  *subject,
                                const gchar    *action_id)
{
        PolkitAuthorizationClaim *authorization_claim;

        authorization_claim = POLKIT_AUTHORIZATION_CLAIM (g_object_new (POLKIT_TYPE_AUTHORIZATION_CLAIM,
                                                                        "subject", subject,
                                                                        "action-id", action_id,
                                                                        NULL));

        return authorization_claim;
}

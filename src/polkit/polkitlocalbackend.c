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
#include "polkiterror.h"
#include "polkitlocalbackend.h"
#include "polkitserialization.h" /* TODO: remove */

/**
 * SECTION:polkitlocalbackend
 * @short_description: Backend using local files
 * @include: polkit/polkit.h
 *
 * The #PolkitLocalBackend class is an implementation of
 * #PolkitBackend that stores authorizations on the local file
 * system.
 */

struct _PolkitLocalBackendPrivate
{
        int stuff;
};

static gchar *say_hello (PolkitBackend        *_backend,
                         PolkitSubject        *inquirer,
                         const gchar          *name,
                         GError              **error);

static PolkitAuthorizationResult check_claims (PolkitBackend       *_backend,
                                               PolkitSubject       *inquirer,
                                               GList               *claims,
                                               GError             **error);

G_DEFINE_TYPE (PolkitLocalBackend, polkit_local_backend, POLKIT_TYPE_BACKEND);

#define POLKIT_LOCAL_BACKEND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_LOCAL_BACKEND, PolkitLocalBackendPrivate))

static void
polkit_local_backend_finalize (GObject *object)
{
        PolkitLocalBackend *local_backend;

        local_backend = POLKIT_LOCAL_BACKEND (object);

        G_OBJECT_CLASS (polkit_local_backend_parent_class)->finalize (object);
}

static void
polkit_local_backend_class_init (PolkitLocalBackendClass *klass)
{
        GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
        PolkitBackendClass *backend_class = POLKIT_BACKEND_CLASS (klass);

        backend_class->say_hello        = say_hello;
        backend_class->check_claims     = check_claims;

        gobject_class->finalize = polkit_local_backend_finalize;

        g_type_class_add_private (klass, sizeof (PolkitLocalBackendPrivate));
}

static void
polkit_local_backend_init (PolkitLocalBackend *local_backend)
{
        local_backend->priv = POLKIT_LOCAL_BACKEND_GET_PRIVATE (local_backend);
}

PolkitBackend *
polkit_local_backend_new (void)
{
        PolkitBackend *backend;

        backend = POLKIT_BACKEND (g_object_new (POLKIT_TYPE_LOCAL_BACKEND, NULL));

        return backend;
}

static gchar *
say_hello (PolkitBackend        *_backend,
           PolkitSubject        *inquirer,
           const gchar          *name,
           GError              **error)
{
        char *ret;

        ret = NULL;

        if (strcmp (name, "davidz") == 0) {
                g_set_error_literal (error,
                                     POLKIT_ERROR,
                                     POLKIT_ERROR_NOT_SUPPORTED,
                                     "We don't want to async greet davidz!");
        } else {
                ret = g_strdup_printf ("Local async greets 'Hi %s!'", name);
        }

        return ret;
}

PolkitAuthorizationResult
check_claims (PolkitBackend       *_backend,
              PolkitSubject       *inquirer,
              GList               *claims,
              GError             **error)
{
        PolkitLocalBackend *backend;
        PolkitAuthorizationResult result;
        GList *l;

        backend = POLKIT_LOCAL_BACKEND (_backend);

        for (l = claims; l != NULL; l = l->next) {
                PolkitAuthorizationClaim *claim = POLKIT_AUTHORIZATION_CLAIM (l->data);
                char *action_id;
                PolkitSubject *subject;
                GHashTable *attributes;
                GHashTableIter iter;
                const char *key;
                const char *value;

                g_object_get (claim,
                              "subject", &subject,
                              "action-id", &action_id,
                              "attributes", &attributes,
                              NULL);

                g_print ("action-id: %s\n", action_id);
                g_print ("subject:   %s\n", _subject_to_string (subject));

                g_hash_table_iter_init (&iter, attributes);
                while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value)) {
                        g_print ("  '%s' -> '%s'\n", key, value);
                }

                g_print ("\n");

                g_object_unref (subject);
                g_free (action_id);
                g_hash_table_unref (attributes);
        }

        /* TODO */
        result = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;

        return result;
}

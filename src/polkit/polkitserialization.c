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
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus-glib.h>

#include <polkit/polkitserialization.h>
#include <polkit/polkituser.h>
#include <polkit/polkitprocess.h>

PolkitAuthorizationResult
_authorization_result_from_string (const char *str)
{
        PolkitAuthorizationResult ret;

        g_return_val_if_fail (str != NULL, POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED);

        ret = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

        if (strcmp (str, "authorized") == 0) {
                ret = POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
        } else if (strcmp (str, "challenge") == 0) {
                ret = POLKIT_AUTHORIZATION_RESULT_CHALLENGE;
        } else if (strcmp (str, "notauthorized") == 0) {
                ret = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;
        } else {
                g_warning ("unknown authorization result string '%s'", str);
        }

        return ret;
}

char *
_authorization_result_to_string (PolkitAuthorizationResult result)
{
        char *ret;

        switch (result) {
        case POLKIT_AUTHORIZATION_RESULT_AUTHORIZED:
                ret = g_strdup ("authorized");
                break;
        case POLKIT_AUTHORIZATION_RESULT_CHALLENGE:
                ret = g_strdup ("challenge");
                break;
        default:
                g_warning ("unknown authorization result with code %d", result);
                /* explicit fallthrough */
        case POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED:
                ret = g_strdup ("notauthorized");
                break;
        }

        return ret;
}

PolkitSubject *
_subject_from_string (const char *str)
{
        PolkitSubject *subject;

        g_return_val_if_fail (str != NULL, NULL);

        subject = NULL;

        if (g_str_has_prefix (str, "user:")) {
                subject = polkit_user_new (str + sizeof ("user:") - 1);
        } else if (g_str_has_prefix (str, "process:")) {
                pid_t pid;
                pid = (pid_t) (atoi (str + sizeof ("process:") - 1));
                subject = polkit_process_new ((pid));
        } else {
                g_warning ("Please add support for deserializing strings of form '%s'", str);
        }

        return subject;
}

char *
_subject_to_string (PolkitSubject *subject)
{
        char *ret;

        g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), NULL);

        ret = NULL;

        if (POLKIT_IS_USER (subject)) {
                char *s;
                s = polkit_user_get_user_name (POLKIT_USER (subject));
                ret = g_strdup_printf ("user:%s", s);
                g_free (s);
        } else if (POLKIT_IS_PROCESS (subject)) {
                pid_t pid;
                pid = polkit_process_get_pid (POLKIT_PROCESS (subject));
                ret = g_strdup_printf ("process:%d", pid);
        } else {
                g_warning ("Please add support for serializing type %s",
                           g_type_name (G_TYPE_FROM_INSTANCE (subject)));
        }

        return ret;
}


#define CLAIM_STRUCT_TYPE (dbus_g_type_get_struct ("GValueArray",     \
                                                   G_TYPE_STRING,     \
                                                   G_TYPE_STRING,     \
                                                   dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_STRING), \
                                                   G_TYPE_INVALID))

void
_authorization_claim_to_value (PolkitAuthorizationClaim *claim, GValue *value)
{
  char *action_id;
  char *subject_str;
  PolkitSubject *subject;
  GHashTable *attributes;

  subject = polkit_authorization_claim_get_subject (claim);
  action_id = polkit_authorization_claim_get_action_id (claim);
  subject_str = _subject_to_string (subject);

  attributes = polkit_authorization_claim_get_attributes (claim);

  g_value_init (value, CLAIM_STRUCT_TYPE);
  g_value_take_boxed (value, dbus_g_type_specialized_construct (CLAIM_STRUCT_TYPE));
  dbus_g_type_struct_set (value,
                          0, subject_str,
                          1, action_id,
                          2, attributes,
                          G_MAXUINT);

  g_free (action_id);
  g_free (subject_str);
  g_object_unref (subject);
}

PolkitAuthorizationClaim *
_authorization_claim_from_data (gpointer data)
{
        GValue elem0 = {0};
        PolkitAuthorizationClaim *claim;
        PolkitSubject *subject;
        char *subject_str;
        char *action_id;
        GHashTable *attributes;
        GHashTableIter iter;
        const char *key;
        const char *value;

        claim = NULL;

        g_value_init (&elem0, CLAIM_STRUCT_TYPE);
        g_value_set_static_boxed (&elem0, data);
        dbus_g_type_struct_get (&elem0,
                                0, &subject_str,
                                1, &action_id,
                                2, &attributes,
                                G_MAXUINT);

        subject = _subject_from_string (subject_str);
        if (subject == NULL)
                goto out;

        claim = polkit_authorization_claim_new (subject, action_id);
        g_hash_table_iter_init (&iter, attributes);
        while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value)) {
                polkit_authorization_claim_set_attribute (claim, key, value);
        }

 out:
        g_free (subject_str);
        g_free (action_id);
        if (subject != NULL)
                g_object_unref (subject);
        if (attributes != NULL)
                g_hash_table_unref (attributes);
        return claim;
}

GList *
_serialize_ptr_array_to_obj_list (GPtrArray                   *ptr_array,
                                  PolkitSerializeToObjectFunc  func)
{
        GList *ret;
        int n;

        ret = NULL;
        for (n = 0; n < (int) ptr_array->len; n++) {
                GObject *object;
                object = func (ptr_array->pdata[n]);
                if (object == NULL)
                        goto fail;
                ret = g_list_prepend (ret, object);
        }
        ret = g_list_reverse (ret);
        return ret;
 fail:
        g_list_foreach (ret, (GFunc) g_object_unref, NULL);
        g_list_free (ret);
        return NULL;
}

GPtrArray *
_serialize_ptr_array_from_obj_list (GList                         *list,
                                    PolkitSerializeFromObjectFunc  func)
{
        GPtrArray *ptr_array;
        GList *l;

        ptr_array = g_ptr_array_new ();
        for (l = list; l != NULL; l = l->next) {
                GObject *object = G_OBJECT (l->data);
                GValue elem = {0};

                func (object, &elem);

                g_ptr_array_add (ptr_array, g_value_get_boxed (&elem));
        }

        return ptr_array;
}

void
_free_serialized_obj_ptr_array (GPtrArray *ptr_array)
{
        g_ptr_array_foreach (ptr_array, (GFunc) g_value_array_free, NULL);
        g_ptr_array_free (ptr_array, TRUE);
}

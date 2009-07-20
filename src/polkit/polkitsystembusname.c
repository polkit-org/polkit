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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>
#include "polkitsystembusname.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitsystembusname
 * @title: PolkitSystemBusName
 * @short_description: Unique system bus names
 *
 * An object that represents a process owning a unique name on the system bus.
 */

/**
 * PolkitUnixSystemBusName:
 *
 * The #PolkitSystemBusName struct should not be accessed directly.
 */
struct _PolkitSystemBusName
{
  GObject parent_instance;

  gchar *name;
};

struct _PolkitSystemBusNameClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_NAME,
};

static void subject_iface_init (PolkitSubjectIface *subject_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitSystemBusName, polkit_system_bus_name, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_system_bus_name_init (PolkitSystemBusName *system_bus_name)
{
}

static void
polkit_system_bus_name_finalize (GObject *object)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (object);

  g_free (system_bus_name->name);

  if (G_OBJECT_CLASS (polkit_system_bus_name_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_system_bus_name_parent_class)->finalize (object);
}

static void
polkit_system_bus_name_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (object);

  switch (prop_id)
    {
    case PROP_NAME:
      g_value_set_string (value, system_bus_name->name);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_system_bus_name_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (object);

  switch (prop_id)
    {
    case PROP_NAME:
      polkit_system_bus_name_set_name (system_bus_name, g_value_get_string (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_system_bus_name_class_init (PolkitSystemBusNameClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_system_bus_name_get_property;
  gobject_class->set_property = polkit_system_bus_name_set_property;
  gobject_class->finalize     = polkit_system_bus_name_finalize;

  /**
   * PolkitSystemBusName:name:
   *
   * The unique name on the system message bus.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_NAME,
                                   g_param_spec_string ("name",
                                                        "Name",
                                                        "The unique name on the system message bus",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

}

/**
 * polkit_system_bus_name_get_name:
 * @system_bus_name: A #PolkitSystemBusName.
 *
 * Gets the unique system bus name for @system_bus_name.
 *
 * Returns: The unique system bus name for @system_bus_name. Do not
 * free, this string is owned by @system_bus_name.
 */
const gchar *
polkit_system_bus_name_get_name (PolkitSystemBusName *system_bus_name)
{
  return system_bus_name->name;
}

/**
 * polkit_system_bus_name_set_name:
 * @system_bus_name: A #PolkitSystemBusName.
 * @name: A unique system bus name.
 *
 * Sets the unique system bus name for @system_bus_name.
 */
void
polkit_system_bus_name_set_name (PolkitSystemBusName *system_bus_name,
                                 const gchar         *name)
{
  g_free (system_bus_name->name);
  system_bus_name->name = g_strdup (name);
}

/**
 * polkit_system_bus_name_new:
 * @name: A unique system bus name.
 *
 * Creates a new #PolkitSystemBusName for @name.
 *
 * Returns: A #PolkitSystemBusName. Free with g_object_unref().
 */
PolkitSubject *
polkit_system_bus_name_new (const gchar *name)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_SYSTEM_BUS_NAME,
                                       "name", name,
                                       NULL));
}

static guint
polkit_system_bus_name_hash (PolkitSubject *subject)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (subject);

  return g_str_hash (system_bus_name->name);
}

static gboolean
polkit_system_bus_name_equal (PolkitSubject *a,
                              PolkitSubject *b)
{
  PolkitSystemBusName *name_a;
  PolkitSystemBusName *name_b;

  name_a = POLKIT_SYSTEM_BUS_NAME (a);
  name_b = POLKIT_SYSTEM_BUS_NAME (b);

  return strcmp (name_a->name, name_b->name) == 0;
}

static gchar *
polkit_system_bus_name_to_string (PolkitSubject *subject)
{
  PolkitSystemBusName *system_bus_name = POLKIT_SYSTEM_BUS_NAME (subject);

  return g_strdup_printf ("system-bus-name:%s", system_bus_name->name);
}


static void
name_exists_cb (GObject      *source_object,
                GAsyncResult *res,
                gpointer      user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  EggDBusMessage *reply;
  GError *error;

  error = NULL;
  reply = egg_dbus_connection_send_message_with_reply_finish (EGG_DBUS_CONNECTION (source_object),
                                                              res,
                                                              &error);
  if (reply != NULL)
    {
      gboolean has_owner;
      if (egg_dbus_message_extract_boolean (reply, &has_owner, &error))
        {
          g_simple_async_result_set_op_res_gboolean (simple, has_owner);
        }
      g_object_unref (reply);
    }

  if (error != NULL)
    {
      g_simple_async_result_set_from_error (simple, error);
      g_error_free (error);
    }

  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

static void
polkit_system_bus_name_exists (PolkitSubject       *subject,
                               GCancellable        *cancellable,
                               GAsyncReadyCallback  callback,
                               gpointer             user_data)
{
  PolkitSystemBusName *name = POLKIT_SYSTEM_BUS_NAME (subject);
  EggDBusMessage *message;
  EggDBusConnection *connection;
  GSimpleAsyncResult *simple;

  message = NULL;
  connection = NULL;

  connection = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  message = egg_dbus_connection_new_message_for_method_call (connection,
                                                             NULL,
                                                             "org.freedesktop.DBus",
                                                             "/org/freedesktop/DBus",
                                                             "org.freedesktop.DBus",
                                                             "NameHasOwner");
  egg_dbus_message_append_string (message, name->name, NULL);

  simple = g_simple_async_result_new (G_OBJECT (name),
                                      callback,
                                      user_data,
                                      polkit_system_bus_name_exists);

  egg_dbus_connection_send_message_with_reply (connection,
                                               EGG_DBUS_CALL_FLAGS_NONE,
                                               message,
                                               NULL,
                                               cancellable,
                                               name_exists_cb,
                                               simple);

  g_object_unref (message);
  g_object_unref (connection);
}

static gboolean
polkit_system_bus_name_exists_sync (PolkitSubject   *subject,
                                    GCancellable    *cancellable,
                                    GError         **error)
{
  PolkitSystemBusName *name = POLKIT_SYSTEM_BUS_NAME (subject);
  EggDBusMessage *message;
  EggDBusMessage *reply;
  EggDBusConnection *connection;
  gboolean ret;

  message = NULL;
  reply = NULL;
  connection = NULL;
  ret = FALSE;

  connection = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  message = egg_dbus_connection_new_message_for_method_call (connection,
                                                             NULL,
                                                             "org.freedesktop.DBus",
                                                             "/org/freedesktop/DBus",
                                                             "org.freedesktop.DBus",
                                                             "NameHasOwner");
  egg_dbus_message_append_string (message, name->name, NULL);

  reply = egg_dbus_connection_send_message_with_reply_sync (connection,
                                                            EGG_DBUS_CALL_FLAGS_NONE,
                                                            message,
                                                            NULL,
                                                            cancellable,
                                                            error);
  if (reply == NULL)
    goto out;

  if (!egg_dbus_message_extract_boolean (reply, &ret, error))
    goto out;

 out:
  if (message != NULL)
    g_object_unref (message);
  if (reply != NULL)
    g_object_unref (reply);
  if (connection != NULL)
    g_object_unref (connection);

  return ret;
}

static gboolean
polkit_system_bus_name_exists_finish (PolkitSubject  *subject,
                                      GAsyncResult   *res,
                                      GError        **error)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);
  gboolean ret;

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_system_bus_name_exists);

  ret = FALSE;

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

  ret = g_simple_async_result_get_op_res_gboolean (simple);

 out:
  return ret;
}

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->hash          = polkit_system_bus_name_hash;
  subject_iface->equal         = polkit_system_bus_name_equal;
  subject_iface->to_string     = polkit_system_bus_name_to_string;
  subject_iface->exists        = polkit_system_bus_name_exists;
  subject_iface->exists_finish = polkit_system_bus_name_exists_finish;
  subject_iface->exists_sync   = polkit_system_bus_name_exists_sync;
}

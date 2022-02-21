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
#include "polkitunixuser.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

#include "polkitunixprocess.h"

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


guint8 dbus_call_respond_fails;      // has to be global because of callback


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
  g_return_val_if_fail (POLKIT_IS_SYSTEM_BUS_NAME (system_bus_name), NULL);
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
  g_return_if_fail (POLKIT_IS_SYSTEM_BUS_NAME (system_bus_name));
  g_return_if_fail (g_dbus_is_unique_name (name));
  g_free (system_bus_name->name);
  system_bus_name->name = g_strdup (name);
}

/**
 * polkit_system_bus_name_new:
 * @name: A unique system bus name.
 *
 * Creates a new #PolkitSystemBusName for @name.
 *
 * Returns: (transfer full): A #PolkitSystemBusName. Free with g_object_unref().
 */
PolkitSubject *
polkit_system_bus_name_new (const gchar *name)
{
  g_return_val_if_fail (g_dbus_is_unique_name (name), NULL);
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

static gboolean
polkit_system_bus_name_exists_sync (PolkitSubject   *subject,
                                    GCancellable    *cancellable,
                                    GError         **error)
{
  PolkitSystemBusName *name = POLKIT_SYSTEM_BUS_NAME (subject);
  GDBusConnection *connection;
  GVariant *result;
  gboolean ret;

  ret = FALSE;

  connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, cancellable, error);
  if (connection == NULL)
    goto out;

  result = g_dbus_connection_call_sync (connection,
                                        "org.freedesktop.DBus",   /* name */
                                        "/org/freedesktop/DBus",  /* object path */
                                        "org.freedesktop.DBus",   /* interface name */
                                        "NameHasOwner",           /* method */
                                        g_variant_new ("(s)", name->name),
                                        G_VARIANT_TYPE ("(b)"),
                                        G_DBUS_CALL_FLAGS_NONE,
                                        -1,
                                        cancellable,
                                        error);
  if (result == NULL)
    goto out;

  g_variant_get (result, "(b)", &ret);
  g_variant_unref (result);

 out:
  if (connection != NULL)
    g_object_unref (connection);
  return ret;
}

static void
exists_in_thread_func (GSimpleAsyncResult *res,
                       GObject            *object,
                       GCancellable       *cancellable)
{
  GError *error;
  error = NULL;
  if (!polkit_system_bus_name_exists_sync (POLKIT_SUBJECT (object),
                                           cancellable,
                                           &error))
    {
      g_simple_async_result_set_from_error (res, error);
      g_error_free (error);
    }
}

static void
polkit_system_bus_name_exists (PolkitSubject       *subject,
                               GCancellable        *cancellable,
                               GAsyncReadyCallback  callback,
                               gpointer             user_data)
{
  GSimpleAsyncResult *simple;

  g_return_if_fail (POLKIT_IS_SYSTEM_BUS_NAME (subject));

  simple = g_simple_async_result_new (G_OBJECT (subject),
                                      callback,
                                      user_data,
                                      polkit_system_bus_name_exists);
  g_simple_async_result_run_in_thread (simple,
                                       exists_in_thread_func,
                                       G_PRIORITY_DEFAULT,
                                       cancellable);
  g_object_unref (simple);
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

/* ---------------------------------------------------------------------------------------------------- */

typedef struct {
  GError **error;
  guint retrieved_uid : 1;
  guint retrieved_pid : 1;
  guint caught_error : 1;

  guint32 uid;
  guint32 pid;
} AsyncGetBusNameCredsData;

static void
on_retrieved_unix_uid_pid (GObject              *src,
			   GAsyncResult         *res,
			   gpointer              user_data)
{
  AsyncGetBusNameCredsData *data = user_data;
  GVariant *v;

  v = g_dbus_connection_call_finish ((GDBusConnection*)src, res,
				     data->caught_error ? NULL : data->error);
  if (!v)
    {
      data->caught_error = TRUE;
      dbus_call_respond_fails += 1;
    }
  else
    {
      guint32 value;
      g_variant_get (v, "(u)", &value);
      g_variant_unref (v);
      if (!data->retrieved_uid)
	{
	  data->retrieved_uid = TRUE;
	  data->uid = value;
	}
      else
	{
	  g_assert (!data->retrieved_pid);
	  data->retrieved_pid = TRUE;
	  data->pid = value;
	}
    }
}

static gboolean
polkit_system_bus_name_get_creds_sync (PolkitSystemBusName           *system_bus_name,
				       guint32                       *out_uid,
				       guint32                       *out_pid,
				       GCancellable                  *cancellable,
				       GError                       **error)
{
  gboolean ret = FALSE;
  AsyncGetBusNameCredsData data = { 0, };
  GDBusConnection *connection = NULL;
  GMainContext *tmp_context = NULL;

  connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, cancellable, error);
  if (connection == NULL)
    goto out;

  data.error = error;

  tmp_context = g_main_context_new ();
  g_main_context_push_thread_default (tmp_context);

  dbus_call_respond_fails = 0;

  /* Do two async calls as it's basically as fast as one sync call.
   */
  g_dbus_connection_call (connection,
			  "org.freedesktop.DBus",       /* name */
			  "/org/freedesktop/DBus",      /* object path */
			  "org.freedesktop.DBus",       /* interface name */
			  "GetConnectionUnixUser",      /* method */
			  g_variant_new ("(s)", system_bus_name->name),
			  G_VARIANT_TYPE ("(u)"),
			  G_DBUS_CALL_FLAGS_NONE,
			  -1,
			  cancellable,
			  on_retrieved_unix_uid_pid,
			  &data);
  g_dbus_connection_call (connection,
			  "org.freedesktop.DBus",       /* name */
			  "/org/freedesktop/DBus",      /* object path */
			  "org.freedesktop.DBus",       /* interface name */
			  "GetConnectionUnixProcessID", /* method */
			  g_variant_new ("(s)", system_bus_name->name),
			  G_VARIANT_TYPE ("(u)"),
			  G_DBUS_CALL_FLAGS_NONE,
			  -1,
			  cancellable,
			  on_retrieved_unix_uid_pid,
			  &data);

  while (TRUE)
  {
    /* If one dbus call returns error, we must wait until the other call
     * calls _call_finish(), otherwise fd leak is possible.
     * Resolves: GHSL-2021-077
    */

    if ( (dbus_call_respond_fails > 1) )
    {
      // we got two faults, we can leave
      goto out;
    }

    if ((data.caught_error && (data.retrieved_pid || data.retrieved_uid)))
    {
      // we got one fault and the other call finally finished, we can leave
      goto out;
    }

    if ( !(data.retrieved_uid && data.retrieved_pid) )
    {
      g_main_context_iteration (tmp_context, TRUE);
    }
    else
    {
      break;
    }
  }

  if (out_uid)
    *out_uid = data.uid;
  if (out_pid)
    *out_pid = data.pid;
  ret = TRUE;
 out:
  if (tmp_context)
    {
      g_main_context_pop_thread_default (tmp_context);
      g_main_context_unref (tmp_context);
    }
  if (connection != NULL)
    g_object_unref (connection);
  return ret;
}

/**
 * polkit_system_bus_name_get_process_sync:
 * @system_bus_name: A #PolkitSystemBusName.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronously gets a #PolkitUnixProcess object for @system_bus_name
 * - the calling thread is blocked until a reply is received.
 *
 * Returns: (allow-none) (transfer full): A #PolkitUnixProcess object or %NULL if @error is set.
 **/
PolkitSubject *
polkit_system_bus_name_get_process_sync (PolkitSystemBusName  *system_bus_name,
                                         GCancellable         *cancellable,
                                         GError              **error)
{
  PolkitSubject *ret = NULL;
  guint32 pid;
  guint32 uid;

  g_return_val_if_fail (POLKIT_IS_SYSTEM_BUS_NAME (system_bus_name), NULL);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  if (!polkit_system_bus_name_get_creds_sync (system_bus_name, &uid, &pid,
					      cancellable, error))
    goto out;

  ret = polkit_unix_process_new_for_owner (pid, 0, uid);

 out:
  return ret;
}

/**
 * polkit_system_bus_name_get_user_sync:
 * @system_bus_name: A #PolkitSystemBusName.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronously gets a #PolkitUnixUser object for @system_bus_name;
 * the calling thread is blocked until a reply is received.
 *
 * Returns: (allow-none) (transfer full): A #PolkitUnixUser object or %NULL if @error is set.
 **/
PolkitUnixUser *
polkit_system_bus_name_get_user_sync (PolkitSystemBusName  *system_bus_name,
				      GCancellable         *cancellable,
				      GError              **error)
{
  PolkitUnixUser *ret = NULL;
  guint32 uid;

  g_return_val_if_fail (POLKIT_IS_SYSTEM_BUS_NAME (system_bus_name), NULL);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  if (!polkit_system_bus_name_get_creds_sync (system_bus_name, &uid, NULL,
					      cancellable, error))
    goto out;

  ret = (PolkitUnixUser*)polkit_unix_user_new (uid);

 out:
  return ret;
}

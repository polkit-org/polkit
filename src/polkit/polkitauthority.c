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

#include "polkitauthorizationresult.h"
#include "polkitcheckauthorizationflags.h"
#include "polkitauthority.h"
#include "polkiterror.h"
#include "polkitenumtypes.h"
#include "polkitsubject.h"
#include "polkitidentity.h"
#include "polkitdetails.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitauthority
 * @title: PolkitAuthority
 * @short_description: Authority
 * @stability: Stable
 *
 * #PolkitAuthority is used for checking whether a given subject is
 * authorized to perform a given action. Typically privileged system
 * daemons or suid helpers will use this when handling requests from
 * untrusted clients.
 *
 * User sessions can register an authentication agent with the
 * authority. This is used for requests from untrusted clients where
 * system policy requires that the user needs to acknowledge (through
 * proving he is the user or the administrator) a given action. See
 * #PolkitAgentListener and #PolkitAgentSession for details.
 */

/**
 * PolkitAuthority:
 *
 * The #PolkitAuthority struct should not be accessed directly.
 */
struct _PolkitAuthority
{
  /*< private >*/
  GObject parent_instance;

  gchar *name;
  gchar *version;

  GDBusProxy *proxy;
  guint cancellation_id_counter;

  gboolean initialized;
  GError *initialization_error;
};

struct _PolkitAuthorityClass
{
  GObjectClass parent_class;

};

G_LOCK_DEFINE_STATIC (the_lock);
static PolkitAuthority *the_authority = NULL;

enum
{
  CHANGED_SIGNAL,
  LAST_SIGNAL,
};

enum
{
  PROP_0,
  PROP_OWNER,
  PROP_BACKEND_NAME,
  PROP_BACKEND_VERSION,
  PROP_BACKEND_FEATURES
};

static guint signals[LAST_SIGNAL] = {0};

static void initable_iface_init       (GInitableIface *initable_iface);
static void async_initable_iface_init (GAsyncInitableIface *async_initable_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitAuthority, polkit_authority, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_ASYNC_INITABLE, async_initable_iface_init))

static void
on_proxy_signal (GDBusProxy   *proxy,
                 const gchar  *sender_name,
                 const gchar  *signal_name,
                 GVariant     *parameters,
                 gpointer      user_data)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (user_data);
  if (g_strcmp0 (signal_name, "Changed") == 0)
    {
      g_signal_emit_by_name (authority, "changed");
    }
}

static void
on_notify_g_name_owner (GObject    *object,
                        GParamSpec *ppsec,
                        gpointer    user_data)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (user_data);
  g_object_notify (G_OBJECT (authority), "owner");
}

static void
polkit_authority_init (PolkitAuthority *authority)
{
}

static void
polkit_authority_dispose (GObject *object)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (object);

  G_LOCK (the_lock);
  if (authority == the_authority)
    the_authority = NULL;
  G_UNLOCK (the_lock);

  if (G_OBJECT_CLASS (polkit_authority_parent_class)->dispose != NULL)
    G_OBJECT_CLASS (polkit_authority_parent_class)->dispose (object);
}

static void
polkit_authority_finalize (GObject *object)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (object);

  if (authority->initialization_error != NULL)
    g_error_free (authority->initialization_error);

  g_free (authority->name);
  g_free (authority->version);
  if (authority->proxy != NULL)
    g_object_unref (authority->proxy);

  if (G_OBJECT_CLASS (polkit_authority_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_authority_parent_class)->finalize (object);
}

static void
polkit_authority_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (object);

  switch (prop_id)
    {
    case PROP_OWNER:
      g_value_take_string (value, polkit_authority_get_owner (authority));
      break;

    case PROP_BACKEND_NAME:
      g_value_set_string (value, polkit_authority_get_backend_name (authority));
      break;

    case PROP_BACKEND_VERSION:
      g_value_set_string (value, polkit_authority_get_backend_version (authority));
      break;

    case PROP_BACKEND_FEATURES:
      g_value_set_flags (value, polkit_authority_get_backend_features (authority));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_authority_class_init (PolkitAuthorityClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose      = polkit_authority_dispose;
  gobject_class->finalize     = polkit_authority_finalize;
  gobject_class->get_property = polkit_authority_get_property;

  /**
   * PolkitAuthority:owner:
   *
   * The unique name of the owner of the org.freedesktop.PolicyKit1
   * D-Bus service or %NULL if there is no owner. Connect to the
   * #GObject::notify signal to track changes to this property.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_OWNER,
                                   g_param_spec_string ("owner",
                                                        "Owner",
                                                        "Owner.",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitAuthority:backend-name:
   *
   * The name of the currently used Authority backend.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_BACKEND_NAME,
                                   g_param_spec_string ("backend-name",
                                                        "Backend name",
                                                        "The name of the currently used Authority backend.",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitAuthority:version:
   *
   * The version of the currently used Authority backend.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_BACKEND_VERSION,
                                   g_param_spec_string ("backend-version",
                                                        "Backend version",
                                                        "The version of the currently used Authority backend.",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitAuthority:backend-features:
   *
   * The features of the currently used Authority backend.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_BACKEND_FEATURES,
                                   g_param_spec_flags ("backend-features",
                                                       "Backend features",
                                                       "The features of the currently used Authority backend.",
                                                       POLKIT_TYPE_AUTHORITY_FEATURES,
                                                       POLKIT_AUTHORITY_FEATURES_NONE,
                                                       G_PARAM_READABLE |
                                                       G_PARAM_STATIC_NAME |
                                                       G_PARAM_STATIC_NICK |
                                                       G_PARAM_STATIC_BLURB));

  /**
   * PolkitAuthority::changed:
   * @authority: A #PolkitAuthority.
   *
   * Emitted when actions and/or authorizations change
   */
  signals[CHANGED_SIGNAL] = g_signal_new ("changed",
                                          POLKIT_TYPE_AUTHORITY,
                                          G_SIGNAL_RUN_LAST,
                                          0,                      /* class offset     */
                                          NULL,                   /* accumulator      */
                                          NULL,                   /* accumulator data */
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE,
                                          0);
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
polkit_authority_initable_init (GInitable     *initable,
                                GCancellable  *cancellable,
                                GError       **error)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (initable);
  gboolean ret;

  /* This method needs to be idempotent to work with the singleton
   * pattern. See the docs for g_initable_init(). We implement this by
   * locking.
   */

  ret = FALSE;

  G_LOCK (the_lock);
  if (authority->initialized)
    {
      if (authority->initialization_error == NULL)
        ret = TRUE;
      goto out;
    }

  authority->proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                                    G_DBUS_PROXY_FLAGS_NONE,
                                                    NULL, /* TODO: pass GDBusInterfaceInfo* */
                                                    "org.freedesktop.PolicyKit1",            /* name */
                                                    "/org/freedesktop/PolicyKit1/Authority", /* path */
                                                    "org.freedesktop.PolicyKit1.Authority",  /* interface */
                                                    cancellable,
                                                    &authority->initialization_error);
  if (authority->proxy == NULL)
    {
      g_prefix_error (&authority->initialization_error, "Error initializing authority: ");
      goto out;
    }
  g_signal_connect (authority->proxy,
                    "g-signal",
                    G_CALLBACK (on_proxy_signal),
                    authority);
  g_signal_connect (authority->proxy,
                    "notify::g-name-owner",
                    G_CALLBACK (on_notify_g_name_owner),
                    authority);

  ret = TRUE;

 out:
  authority->initialized = TRUE;

  if (!ret)
    {
      g_assert (authority->initialization_error != NULL);
      g_propagate_error (error, g_error_copy (authority->initialization_error));
    }
  G_UNLOCK (the_lock);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
initable_iface_init (GInitableIface *initable_iface)
{
  initable_iface->init = polkit_authority_initable_init;
}

static void
async_initable_iface_init (GAsyncInitableIface *async_initable_iface)
{
  /* for now, we use default implementation to run GInitable code in a
   * thread - would probably be nice to have real async version to
   * avoid the thread-overhead
   */
}

/* ---------------------------------------------------------------------------------------------------- */

/* deprecated, see polkitauthority.h */

/**
 * polkit_authority_get:
 *
 * (deprecated)
 *
 * Returns: (transfer full): value
 */
PolkitAuthority *
polkit_authority_get (void)
{
  GError *error;
  PolkitAuthority *ret;

  error = NULL;
  ret = polkit_authority_get_sync (NULL, /* GCancellable* */
                                   &error);
  if (ret == NULL)
    {
      g_warning ("polkit_authority_get: Error getting authority: %s",
                 error->message);
      g_error_free (error);
    }

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static PolkitAuthority *
get_uninitialized_authority (GCancellable *cancellable,
                             GError       **error)
{
  static volatile GQuark error_quark = 0;

  G_LOCK (the_lock);
  if (error_quark == 0)
    error_quark = POLKIT_ERROR;

  if (the_authority != NULL)
    {
      g_object_ref (the_authority);
      goto out;
    }
  the_authority = POLKIT_AUTHORITY (g_object_new (POLKIT_TYPE_AUTHORITY, NULL));
 out:
  G_UNLOCK (the_lock);
  return the_authority;
}

static void
authority_get_async_cb (GObject      *source_object,
                        GAsyncResult *res,
                        gpointer      user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  GError *error;

  error = NULL;
  if (!g_async_initable_init_finish (G_ASYNC_INITABLE (source_object),
                                     res,
                                     &error))
    {
      g_assert (error != NULL);
      g_simple_async_result_set_from_error (simple, error);
      g_error_free (error);
      g_object_unref (source_object);
    }
  else
    {
      g_simple_async_result_set_op_res_gpointer (simple,
                                                 source_object,
                                                 g_object_unref);
    }
  g_simple_async_result_complete_in_idle (simple);
  g_object_unref (simple);
}

/**
 * polkit_authority_get_async:
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously gets a reference to the authority.
 *
 * This is an asynchronous failable function. When the result is
 * ready, @callback will be invoked in the <link
 * linkend="g-main-context-push-thread-default">thread-default main
 * loop</link> of the thread you are calling this method from and you
 * can use polkit_authority_get_finish() to get the result. See
 * polkit_authority_get_sync() for the synchronous version.
 */
void
polkit_authority_get_async  (GCancellable        *cancellable,
                             GAsyncReadyCallback  callback,
                             gpointer             user_data)
{
  PolkitAuthority *authority;
  GSimpleAsyncResult *simple;
  GError *error;

  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  simple = g_simple_async_result_new (NULL,
                                      callback,
                                      user_data,
                                      polkit_authority_get_async);

  error = NULL;
  authority = get_uninitialized_authority (cancellable, &error);
  if (authority == NULL)
    {
      g_assert (error != NULL);
      g_simple_async_result_set_from_error (simple, error);
      g_error_free (error);
      g_simple_async_result_complete_in_idle (simple);
      g_object_unref (simple);
    }
  else
    {
      g_async_initable_init_async (G_ASYNC_INITABLE (authority),
                                   G_PRIORITY_DEFAULT,
                                   cancellable,
                                   authority_get_async_cb,
                                   simple);
    }
}

/**
 * polkit_authority_get_finish:
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to polkit_authority_get_async().
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes an operation started with polkit_authority_get_async().
 *
 * Returns: (transfer full): A #PolkitAuthority. Free it with
 * g_object_unref() when done with it.
 */
PolkitAuthority *
polkit_authority_get_finish (GAsyncResult        *res,
                             GError             **error)
{
  GSimpleAsyncResult *simple;
  GObject *object;
  PolkitAuthority *ret;

  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_get_async);

  ret = NULL;

  if (g_simple_async_result_propagate_error (simple, error))
    goto out;

  object = g_simple_async_result_get_op_res_gpointer (simple);
  g_assert (object != NULL);
  ret = g_object_ref (POLKIT_AUTHORITY (object));

 out:
  return ret;
}

/**
 * polkit_authority_get_sync:
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronously gets a reference to the authority.
 *
 * This is a synchronous failable function - the calling thread is
 * blocked until a reply is received. See polkit_authority_get_async()
 * for the asynchronous version.
 *
 * Returns: (transfer full): A #PolkitAuthority. Free it with
 * g_object_unref() when done with it.
 */
PolkitAuthority *
polkit_authority_get_sync (GCancellable        *cancellable,
                           GError             **error)
{
  PolkitAuthority *authority;

  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  authority = get_uninitialized_authority (cancellable, error);
  if (authority == NULL)
    goto out;

  if (!g_initable_init (G_INITABLE (authority), cancellable, error))
    {
      g_object_unref (authority);
      authority = NULL;
    }

 out:
  return authority;
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  GAsyncResult *res;
  GMainContext *context;
  GMainLoop *loop;
} CallSyncData;

static CallSyncData *
call_sync_new (void)
{
  CallSyncData *data;
  data = g_new0 (CallSyncData, 1);
  data->context = g_main_context_new ();
  data->loop = g_main_loop_new (data->context, FALSE);
  g_main_context_push_thread_default (data->context);
  return data;
}

static void
call_sync_cb (GObject      *source_object,
              GAsyncResult *res,
              gpointer      user_data)
{
  CallSyncData *data = user_data;
  data->res = g_object_ref (res);
  g_main_loop_quit (data->loop);
}

static void
call_sync_block (CallSyncData *data)
{
  g_main_loop_run (data->loop);
}

static void
call_sync_free (CallSyncData *data)
{
  g_main_context_pop_thread_default (data->context);
  g_main_context_unref (data->context);
  g_main_loop_unref (data->loop);
  g_object_unref (data->res);
  g_free (data);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
generic_async_cb (GObject      *source_obj,
                  GAsyncResult *res,
                  gpointer      user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);
  g_simple_async_result_set_op_res_gpointer (simple, g_object_ref (res), g_object_unref);
  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_enumerate_actions:
 * @authority: A #PolkitAuthority.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously retrieves all registered actions.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call polkit_authority_enumerate_actions_finish()
 * to get the result of the operation.
 **/
void
polkit_authority_enumerate_actions (PolkitAuthority     *authority,
                                    GCancellable        *cancellable,
                                    GAsyncReadyCallback  callback,
                                    gpointer             user_data)
{
  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));
  g_dbus_proxy_call (authority->proxy,
                     "EnumerateActions",
                     g_variant_new ("(s)",
                                    ""), /* TODO: use system locale */
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_enumerate_actions));
}

/**
 * polkit_authority_enumerate_actions_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes retrieving all registered actions.
 *
 * Returns: (element-type Polkit.ActionDescription) (transfer full): A list of
 * #PolkitActionDescription objects or %NULL if @error is set. The returned
 * list should be freed with g_list_free() after each element have been freed
 * with g_object_unref().
 **/
GList *
polkit_authority_enumerate_actions_finish (PolkitAuthority *authority,
                                           GAsyncResult    *res,
                                           GError         **error)
{
  GList *ret;
  GVariant *value;
  GVariantIter iter;
  GVariant *child;
  GVariant *array;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  ret = NULL;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_enumerate_actions);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;

  array = g_variant_get_child_value (value, 0);
  g_variant_iter_init (&iter, array);
  while ((child = g_variant_iter_next_value (&iter)) != NULL)
    {
      ret = g_list_prepend (ret, polkit_action_description_new_for_gvariant (child));
      g_variant_unref (child);
    }
  ret = g_list_reverse (ret);
  g_variant_unref (array);
  g_variant_unref (value);

 out:
  return ret;
}

/**
 * polkit_authority_enumerate_actions_sync:
 * @authority: A #PolkitAuthority.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronously retrieves all registered actions - the calling thread
 * is blocked until a reply is received. See
 * polkit_authority_enumerate_actions() for the asynchronous version.
 *
 * Returns: (element-type Polkit.ActionDescription) (transfer full): A list of
 * #PolkitActionDescription or %NULL if @error is set. The returned list should
 * be freed with g_list_free() after each element have been freed with
 * g_object_unref().
 **/
GList *
polkit_authority_enumerate_actions_sync (PolkitAuthority *authority,
                                         GCancellable    *cancellable,
                                         GError         **error)
{
  GList *ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  data = call_sync_new ();
  polkit_authority_enumerate_actions (authority, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_enumerate_actions_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct
{
  PolkitAuthority *authority;
  GSimpleAsyncResult *simple;
  gchar *cancellation_id;
} CheckAuthData;

static void
cancel_check_authorization_cb (GDBusProxy    *proxy,
                               GAsyncResult  *res,
                               gpointer       user_data)
{
  GVariant *value;
  GError *error;

  error = NULL;
  value = g_dbus_proxy_call_finish (proxy, res, &error);
  if (value == NULL)
    {
      g_warning ("Error cancelling authorization check: %s", error->message);
      g_error_free (error);
    }
  else
    {
      g_variant_unref (value);
    }
}

static void
check_authorization_cb (GDBusProxy    *proxy,
                        GAsyncResult  *res,
                        gpointer       user_data)
{
  CheckAuthData *data = user_data;
  GVariant *value;
  GError *error;

  error = NULL;
  value = g_dbus_proxy_call_finish (proxy, res, &error);
  if (value == NULL)
    {
      if (data->cancellation_id != NULL &&
          (!g_dbus_error_is_remote_error (error) &&
           error->domain == G_IO_ERROR &&
           error->code == G_IO_ERROR_CANCELLED))
        {
          g_dbus_proxy_call (data->authority->proxy,
                             "CancelCheckAuthorization",
                             g_variant_new ("(s)", data->cancellation_id),
                             G_DBUS_CALL_FLAGS_NONE,
                             -1,
                             NULL, /* GCancellable */
                             (GAsyncReadyCallback) cancel_check_authorization_cb,
                             NULL);
        }
      g_simple_async_result_set_from_error (data->simple, error);
      g_error_free (error);
    }
  else
    {
      GVariant *result_value;
      PolkitAuthorizationResult *result;
      result_value = g_variant_get_child_value (value, 0);
      result = polkit_authorization_result_new_for_gvariant (result_value);
      g_variant_unref (result_value);
      g_variant_unref (value);
      g_simple_async_result_set_op_res_gpointer (data->simple, result, g_object_unref);
    }

  g_simple_async_result_complete (data->simple);

  g_object_unref (data->authority);
  g_object_unref (data->simple);
  g_free (data->cancellation_id);
  g_free (data);
}

/**
 * polkit_authority_check_authorization:
 * @authority: A #PolkitAuthority.
 * @subject: A #PolkitSubject.
 * @action_id: The action to check for.
 * @details: (allow-none): Details about the action or %NULL.
 * @flags: A set of #PolkitCheckAuthorizationFlags.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously checks if @subject is authorized to perform the action represented
 * by @action_id.
 *
 * Note that %POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION
 * <emphasis>SHOULD</emphasis> be passed <emphasis>ONLY</emphasis> if
 * the event that triggered the authorization check is stemming from
 * an user action, e.g. the user pressing a button or attaching a
 * device.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_check_authorization_finish() to get the result of
 * the operation.
 *
 * Known keys in @details include <literal>polkit.message</literal>
 * and <literal>polkit.gettext_domain</literal> that can be used to
 * override the message shown to the user. See the documentation for
 * the <link linkend="eggdbus-method-org.freedesktop.PolicyKit1.Authority.CheckAuthorization">D-Bus method</link> for more details.
 *
 * If @details is non-empty then the request will fail with
 * #POLKIT_ERROR_FAILED unless the process doing the check itsef is
 * sufficiently authorized (e.g. running as uid 0).
 **/
void
polkit_authority_check_authorization (PolkitAuthority               *authority,
                                      PolkitSubject                 *subject,
                                      const gchar                   *action_id,
                                      PolkitDetails                 *details,
                                      PolkitCheckAuthorizationFlags  flags,
                                      GCancellable                  *cancellable,
                                      GAsyncReadyCallback            callback,
                                      gpointer                       user_data)
{
  CheckAuthData *data;

  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (action_id != NULL);
  g_return_if_fail (details == NULL || POLKIT_IS_DETAILS (details));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  data = g_new0 (CheckAuthData, 1);
  data->authority = g_object_ref (authority);
  data->simple = g_simple_async_result_new (G_OBJECT (authority),
                                            callback,
                                            user_data,
                                            polkit_authority_check_authorization);
  G_LOCK (the_lock);
  if (cancellable != NULL)
    data->cancellation_id = g_strdup_printf ("cancellation-id-%d", authority->cancellation_id_counter++);
  G_UNLOCK (the_lock);

  g_dbus_proxy_call (authority->proxy,
                     "CheckAuthorization",
                     g_variant_new ("(@(sa{sv})s@a{ss}us)",
                                    polkit_subject_to_gvariant (subject), /* A floating value */
                                    action_id,
                                    polkit_details_to_gvariant (details), /* A floating value */
                                    flags,
                                    data->cancellation_id != NULL ? data->cancellation_id : ""),
                     G_DBUS_CALL_FLAGS_NONE,
                     G_MAXINT, /* no timeout */
                     cancellable,
                     (GAsyncReadyCallback) check_authorization_cb,
                     data);
}

/**
 * polkit_authority_check_authorization_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes checking if a subject is authorized for an action.
 *
 * Returns: (transfer full): A #PolkitAuthorizationResult or %NULL if
 * @error is set. Free with g_object_unref().
 **/
PolkitAuthorizationResult *
polkit_authority_check_authorization_finish (PolkitAuthority          *authority,
                                             GAsyncResult             *res,
                                             GError                  **error)
{
  PolkitAuthorizationResult *ret;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  ret = NULL;

  if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
    goto out;

  ret = g_object_ref (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

 out:
  return ret;
}

/**
 * polkit_authority_check_authorization_sync:
 * @authority: A #PolkitAuthority.
 * @subject: A #PolkitSubject.
 * @action_id: The action to check for.
 * @details: (allow-none): Details about the action or %NULL.
 * @flags: A set of #PolkitCheckAuthorizationFlags.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Checks if @subject is authorized to perform the action represented
 * by @action_id.
 *
 * Note that %POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION
 * <emphasis>SHOULD</emphasis> be passed <emphasis>ONLY</emphasis> if
 * the event that triggered the authorization check is stemming from
 * an user action, e.g. the user pressing a button or attaching a
 * device.
 *
 * Note the calling thread is blocked until a reply is received. You
 * should therefore <emphasis>NEVER</emphasis> do this from a GUI
 * thread or a daemon service thread when using the
 * %POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION flag. This
 * is because it may potentially take minutes (or even hours) for the
 * operation to complete because it involves waiting for the user to
 * authenticate.
 *
 * Known keys in @details include <literal>polkit.message</literal>
 * and <literal>polkit.gettext_domain</literal> that can be used to
 * override the message shown to the user. See the documentation for
 * the <link linkend="eggdbus-method-org.freedesktop.PolicyKit1.Authority.CheckAuthorization">D-Bus method</link> for more details.
 *
 * Returns: (transfer full): A #PolkitAuthorizationResult or %NULL if @error is set. Free with g_object_unref().
 */
PolkitAuthorizationResult *
polkit_authority_check_authorization_sync (PolkitAuthority               *authority,
                                           PolkitSubject                 *subject,
                                           const gchar                   *action_id,
                                           PolkitDetails                 *details,
                                           PolkitCheckAuthorizationFlags  flags,
                                           GCancellable                  *cancellable,
                                           GError                       **error)
{
  PolkitAuthorizationResult *ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), NULL);
  g_return_val_if_fail (action_id != NULL, NULL);
  g_return_val_if_fail (details == NULL || POLKIT_IS_DETAILS (details), NULL);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  data = call_sync_new ();
  polkit_authority_check_authorization (authority, subject, action_id, details, flags, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_check_authorization_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_register_authentication_agent:
 * @authority: A #PolkitAuthority.
 * @subject: The subject the authentication agent is for, typically a #PolkitUnixSession object.
 * @locale: The locale of the authentication agent.
 * @object_path: The object path for the authentication agent.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously registers an authentication agent.
 *
 * Note that this should be called by the same effective UID which will be
 * the real UID using the #PolkitAgentSession API or otherwise calling
 * polkit_authority_authentication_agent_response().
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_register_authentication_agent_finish() to get the
 * result of the operation.
 **/
void
polkit_authority_register_authentication_agent (PolkitAuthority      *authority,
                                                PolkitSubject        *subject,
                                                const gchar          *locale,
                                                const gchar          *object_path,
                                                GCancellable         *cancellable,
                                                GAsyncReadyCallback   callback,
                                                gpointer              user_data)
{
  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (locale != NULL);
  g_return_if_fail (g_variant_is_object_path (object_path));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_dbus_proxy_call (authority->proxy,
                     "RegisterAuthenticationAgent",
                     g_variant_new ("(@(sa{sv})ss)",
                                    polkit_subject_to_gvariant (subject), /* A floating value */
                                    locale,
                                    object_path),
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_register_authentication_agent));
}

/**
 * polkit_authority_register_authentication_agent_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes registering an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_register_authentication_agent_finish (PolkitAuthority *authority,
                                                       GAsyncResult    *res,
                                                       GError         **error)
{
  gboolean ret;
  GVariant *value;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  ret = FALSE;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_register_authentication_agent);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;
  ret = TRUE;
  g_variant_unref (value);

 out:
  return ret;
}


/**
 * polkit_authority_register_authentication_agent_sync:
 * @authority: A #PolkitAuthority.
 * @subject: The subject the authentication agent is for, typically a #PolkitUnixSession object.
 * @locale: The locale of the authentication agent.
 * @object_path: The object path for the authentication agent.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Registers an authentication agent.
 *
 * Note that this should be called by the same effective UID which will be
 * the real UID using the #PolkitAgentSession API or otherwise calling
 * polkit_authority_authentication_agent_response().
 *
 * The calling thread is blocked
 * until a reply is received. See
 * polkit_authority_register_authentication_agent() for the
 * asynchronous version.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_register_authentication_agent_sync (PolkitAuthority     *authority,
                                                     PolkitSubject       *subject,
                                                     const gchar         *locale,
                                                     const gchar         *object_path,
                                                     GCancellable        *cancellable,
                                                     GError             **error)
{
  gboolean ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), FALSE);
  g_return_val_if_fail (locale != NULL, FALSE);
  g_return_val_if_fail (g_variant_is_object_path (object_path), FALSE);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = call_sync_new ();
  polkit_authority_register_authentication_agent (authority, subject, locale, object_path, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_register_authentication_agent_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_register_authentication_agent_with_options:
 * @authority: A #PolkitAuthority.
 * @subject: The subject the authentication agent is for, typically a #PolkitUnixSession object.
 * @locale: The locale of the authentication agent.
 * @object_path: The object path for the authentication agent.
 * @options: (allow-none): A #GVariant with options or %NULL.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously registers an authentication agent.
 *
 * Note that this should be called by the same effective UID which will be
 * the real UID using the #PolkitAgentSession API or otherwise calling
 * polkit_authority_authentication_agent_response().
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_register_authentication_agent_with_options_finish() to get the
 * result of the operation.
 **/
void
polkit_authority_register_authentication_agent_with_options (PolkitAuthority      *authority,
                                                             PolkitSubject        *subject,
                                                             const gchar          *locale,
                                                             const gchar          *object_path,
                                                             GVariant             *options,
                                                             GCancellable         *cancellable,
                                                             GAsyncReadyCallback   callback,
                                                             gpointer              user_data)
{
  GVariant *subject_value;

  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (locale != NULL);
  g_return_if_fail (g_variant_is_object_path (object_path));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  subject_value = polkit_subject_to_gvariant (subject);
  g_variant_ref_sink (subject_value);
  if (options != NULL)
    {
      g_dbus_proxy_call (authority->proxy,
                         "RegisterAuthenticationAgentWithOptions",
                         g_variant_new ("(@(sa{sv})ss@a{sv})",
                                        subject_value,
                                        locale,
                                        object_path,
                                        options),
                         G_DBUS_CALL_FLAGS_NONE,
                         -1,
                         cancellable,
                         generic_async_cb,
                         g_simple_async_result_new (G_OBJECT (authority),
                                                    callback,
                                                    user_data,
                                                    polkit_authority_register_authentication_agent_with_options));
    }
  else
    {
      g_dbus_proxy_call (authority->proxy,
                         "RegisterAuthenticationAgent",
                         g_variant_new ("(@(sa{sv})ss)",
                                        subject_value,
                                        locale,
                                        object_path),
                         G_DBUS_CALL_FLAGS_NONE,
                         -1,
                         cancellable,
                         generic_async_cb,
                         g_simple_async_result_new (G_OBJECT (authority),
                                                    callback,
                                                    user_data,
                                                    polkit_authority_register_authentication_agent_with_options));
    }
  g_variant_unref (subject_value);
}

/**
 * polkit_authority_register_authentication_agent_with_options_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes registering an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_register_authentication_agent_with_options_finish (PolkitAuthority *authority,
                                                                    GAsyncResult    *res,
                                                                    GError         **error)
{
  gboolean ret;
  GVariant *value;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  ret = FALSE;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_register_authentication_agent_with_options);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;
  ret = TRUE;
  g_variant_unref (value);

 out:
  return ret;
}


/**
 * polkit_authority_register_authentication_agent_with_options_sync:
 * @authority: A #PolkitAuthority.
 * @subject: The subject the authentication agent is for, typically a #PolkitUnixSession object.
 * @locale: The locale of the authentication agent.
 * @object_path: The object path for the authentication agent.
 * @options: (allow-none): A #GVariant with options or %NULL.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Registers an authentication agent.
 *
 * Note that this should be called by the same effective UID which will be
 * the real UID using the #PolkitAgentSession API or otherwise calling
 * polkit_authority_authentication_agent_response().
 *
 * The calling thread is blocked
 * until a reply is received. See
 * polkit_authority_register_authentication_agent_with_options() for the
 * asynchronous version.
 *
 * Returns: %TRUE if the authentication agent was successfully registered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_register_authentication_agent_with_options_sync (PolkitAuthority     *authority,
                                                                  PolkitSubject       *subject,
                                                                  const gchar         *locale,
                                                                  const gchar         *object_path,
                                                                  GVariant            *options,
                                                                  GCancellable        *cancellable,
                                                                  GError             **error)
{
  gboolean ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), FALSE);
  g_return_val_if_fail (locale != NULL, FALSE);
  g_return_val_if_fail (g_variant_is_object_path (object_path), FALSE);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = call_sync_new ();
  polkit_authority_register_authentication_agent_with_options (authority, subject, locale, object_path, options, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_register_authentication_agent_with_options_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_unregister_authentication_agent:
 * @authority: A #PolkitAuthority.
 * @subject: The subject the authentication agent is for, typically a #PolkitUnixSession object.
 * @object_path: The object path for the authentication agent.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously unregisters an authentication agent.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_unregister_authentication_agent_finish() to get
 * the result of the operation.
 **/
void
polkit_authority_unregister_authentication_agent (PolkitAuthority      *authority,
                                                  PolkitSubject        *subject,
                                                  const gchar          *object_path,
                                                  GCancellable         *cancellable,
                                                  GAsyncReadyCallback   callback,
                                                  gpointer              user_data)
{
  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (g_variant_is_object_path (object_path));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_dbus_proxy_call (authority->proxy,
                     "UnregisterAuthenticationAgent",
                     g_variant_new ("(@(sa{sv})s)",
                                    polkit_subject_to_gvariant (subject), /* A floating value */
                                    object_path),
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_unregister_authentication_agent));
}

/**
 * polkit_authority_unregister_authentication_agent_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes unregistering an authentication agent.
 *
 * Returns: %TRUE if the authentication agent was successfully unregistered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_unregister_authentication_agent_finish (PolkitAuthority *authority,
                                                         GAsyncResult    *res,
                                                         GError         **error)
{
  gboolean ret;
  GVariant *value;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  ret = FALSE;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_unregister_authentication_agent);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;
  ret = TRUE;
  g_variant_unref (value);

 out:
  return ret;
}


/**
 * polkit_authority_unregister_authentication_agent_sync:
 * @authority: A #PolkitAuthority.
 * @subject: The subject the authentication agent is for, typically a #PolkitUnixSession object.
 * @object_path: The object path for the authentication agent.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Unregisters an authentication agent. The calling thread is blocked
 * until a reply is received. See
 * polkit_authority_unregister_authentication_agent() for the
 * asynchronous version.
 *
 * Returns: %TRUE if the authentication agent was successfully unregistered, %FALSE if @error is set.
 **/
gboolean
polkit_authority_unregister_authentication_agent_sync (PolkitAuthority     *authority,
                                                       PolkitSubject       *subject,
                                                       const gchar         *object_path,
                                                       GCancellable        *cancellable,
                                                       GError             **error)
{
  gboolean ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), FALSE);
  g_return_val_if_fail (g_variant_is_object_path (object_path), FALSE);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = call_sync_new ();
  polkit_authority_unregister_authentication_agent (authority, subject, object_path, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_unregister_authentication_agent_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_authentication_agent_response:
 * @authority: A #PolkitAuthority.
 * @cookie: The cookie passed to the authentication agent from the authority.
 * @identity: The identity that was authenticated.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously provide response that @identity successfully authenticated
 * for the authentication request identified by @cookie.
 *
 * This function is only used by the privileged bits of an authentication agent.
 * It will fail if the caller is not sufficiently privileged (typically uid 0).
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_authentication_agent_response_finish() to get the
 * result of the operation.
 **/
void
polkit_authority_authentication_agent_response (PolkitAuthority      *authority,
                                                const gchar          *cookie,
                                                PolkitIdentity       *identity,
                                                GCancellable         *cancellable,
                                                GAsyncReadyCallback   callback,
                                                gpointer              user_data)
{
  /* Note that in reality, this API is only accessible to root, and
   * only called from the setuid helper `polkit-agent-helper-1`.
   *
   * However, because this is currently public API, we avoid
   * triggering warnings from ABI diff type programs by just grabbing
   * the real uid of the caller here.
   */
  uid_t uid = getuid ();

  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (cookie != NULL);
  g_return_if_fail (POLKIT_IS_IDENTITY (identity));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_dbus_proxy_call (authority->proxy,
                     "AuthenticationAgentResponse2",
                     g_variant_new ("(us@(sa{sv}))",
                                    (guint32)uid,
                                    cookie,
                                    polkit_identity_to_gvariant (identity)), /* A floating value */
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_authentication_agent_response));
}

/**
 * polkit_authority_authentication_agent_response_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes providing response from an authentication agent.
 *
 * Returns: %TRUE if @authority acknowledged the call, %FALSE if @error is set.
 **/
gboolean
polkit_authority_authentication_agent_response_finish (PolkitAuthority *authority,
                                                       GAsyncResult    *res,
                                                       GError         **error)
{
  gboolean ret;
  GVariant *value;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  ret = FALSE;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_authentication_agent_response);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;
  ret = TRUE;
  g_variant_unref (value);

 out:
  return ret;
}


/**
 * polkit_authority_authentication_agent_response_sync:
 * @authority: A #PolkitAuthority.
 * @cookie: The cookie passed to the authentication agent from the authority.
 * @identity: The identity that was authenticated.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Provide response that @identity successfully authenticated for the
 * authentication request identified by @cookie. See polkit_authority_authentication_agent_response()
 * for limitations on who is allowed is to call this method.
 *
 * The calling thread is blocked until a reply is received. See
 * polkit_authority_authentication_agent_response() for the
 * asynchronous version.
 *
 * Returns: %TRUE if @authority acknowledged the call, %FALSE if @error is set.
 **/
gboolean
polkit_authority_authentication_agent_response_sync (PolkitAuthority     *authority,
                                                     const gchar         *cookie,
                                                     PolkitIdentity      *identity,
                                                     GCancellable        *cancellable,
                                                     GError             **error)
{
  gboolean ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (cookie != NULL, FALSE);
  g_return_val_if_fail (POLKIT_IS_IDENTITY (identity), FALSE);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = call_sync_new ();
  polkit_authority_authentication_agent_response (authority, cookie, identity, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_authentication_agent_response_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_enumerate_temporary_authorizations:
 * @authority: A #PolkitAuthority.
 * @subject: A #PolkitSubject, typically a #PolkitUnixSession.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously gets all temporary authorizations for @subject.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_enumerate_temporary_authorizations_finish() to get
 * the result of the operation.
 **/
void
polkit_authority_enumerate_temporary_authorizations (PolkitAuthority     *authority,
                                                     PolkitSubject       *subject,
                                                     GCancellable        *cancellable,
                                                     GAsyncReadyCallback  callback,
                                                     gpointer             user_data)
{
  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_dbus_proxy_call (authority->proxy,
                     "EnumerateTemporaryAuthorizations",
                     g_variant_new ("(@(sa{sv}))",
                                    polkit_subject_to_gvariant (subject)), /* A floating value */
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_enumerate_temporary_authorizations));
}

/**
 * polkit_authority_enumerate_temporary_authorizations_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes retrieving all registered actions.
 *
 * Returns: (element-type Polkit.TemporaryAuthorization) (transfer full): A
 * list of #PolkitTemporaryAuthorization objects or %NULL if @error is set. The
 * returned list should be freed with g_list_free() after each element have
 * been freed with g_object_unref().
 **/
GList *
polkit_authority_enumerate_temporary_authorizations_finish (PolkitAuthority *authority,
                                                            GAsyncResult    *res,
                                                            GError         **error)
{
  GList *ret;
  GVariant *value;
  GVariantIter iter;
  GVariant *child;
  GVariant *array;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  ret = NULL;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_enumerate_temporary_authorizations);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;

  array = g_variant_get_child_value (value, 0);
  g_variant_iter_init (&iter, array);
  while ((child = g_variant_iter_next_value (&iter)) != NULL)
    {
      PolkitTemporaryAuthorization *auth;
      auth = polkit_temporary_authorization_new_for_gvariant (child, error);
      g_variant_unref (child);
      if (auth == NULL)
        {
          g_prefix_error (error, "Error serializing return value of EnumerateTemporaryAuthorizations: ");
          g_list_foreach (ret, (GFunc) g_object_unref, NULL);
          g_list_free (ret);
          ret = NULL;
          goto out_array;
        }
      ret = g_list_prepend (ret, auth);
    }
  ret = g_list_reverse (ret);
 out_array:
  g_variant_unref (array);
  g_variant_unref (value);

 out:
  return ret;
}

/**
 * polkit_authority_enumerate_temporary_authorizations_sync:
 * @authority: A #PolkitAuthority.
 * @subject: A #PolkitSubject, typically a #PolkitUnixSession.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronousky gets all temporary authorizations for @subject.
 *
 * The calling thread is blocked until a reply is received. See
 * polkit_authority_enumerate_temporary_authorizations() for the
 * asynchronous version.
 *
 * Returns: (element-type Polkit.TemporaryAuthorization) (transfer full): A
 * list of #PolkitTemporaryAuthorization objects or %NULL if @error is set. The
 * returned list should be freed with g_list_free() after each element have
 * been freed with g_object_unref().
 **/
GList *
polkit_authority_enumerate_temporary_authorizations_sync (PolkitAuthority     *authority,
                                                          PolkitSubject       *subject,
                                                          GCancellable        *cancellable,
                                                          GError             **error)
{
  GList *ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), NULL);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), NULL);
  g_return_val_if_fail (error == NULL || *error == NULL, NULL);

  data = call_sync_new ();
  polkit_authority_enumerate_temporary_authorizations (authority, subject, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_enumerate_temporary_authorizations_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_revoke_temporary_authorizations:
 * @authority: A #PolkitAuthority.
 * @subject: The subject to revoke authorizations from, typically a #PolkitUnixSession.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously revokes all temporary authorizations for @subject.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_revoke_temporary_authorizations_finish() to get
 * the result of the operation.
 **/
void
polkit_authority_revoke_temporary_authorizations (PolkitAuthority     *authority,
                                                  PolkitSubject       *subject,
                                                  GCancellable        *cancellable,
                                                  GAsyncReadyCallback  callback,
                                                  gpointer             user_data)
{
  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (POLKIT_IS_SUBJECT (subject));
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_dbus_proxy_call (authority->proxy,
                     "RevokeTemporaryAuthorizations",
                     g_variant_new ("(@(sa{sv}))",
                                    polkit_subject_to_gvariant (subject)), /* A floating value */
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_revoke_temporary_authorizations));
}

/**
 * polkit_authority_revoke_temporary_authorizations_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes revoking temporary authorizations.
 *
 * Returns: %TRUE if all the temporary authorizations was revoked, %FALSE if error is set.
 **/
gboolean
polkit_authority_revoke_temporary_authorizations_finish (PolkitAuthority *authority,
                                                         GAsyncResult    *res,
                                                         GError         **error)
{
  gboolean ret;
  GVariant *value;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  ret = FALSE;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_revoke_temporary_authorizations);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;
  ret = TRUE;
  g_variant_unref (value);

 out:
  return ret;
}

/**
 * polkit_authority_revoke_temporary_authorizations_sync:
 * @authority: A #PolkitAuthority.
 * @subject: The subject to revoke authorizations from, typically a #PolkitUnixSession.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronously revokes all temporary authorization from @subject.
 *
 * The calling thread is blocked until a reply is received. See
 * polkit_authority_revoke_temporary_authorizations() for the
 * asynchronous version.
 *
 * Returns: %TRUE if the temporary authorization was revoked, %FALSE if error is set.
 **/
gboolean
polkit_authority_revoke_temporary_authorizations_sync (PolkitAuthority     *authority,
                                                       PolkitSubject       *subject,
                                                       GCancellable        *cancellable,
                                                       GError             **error)
{
  gboolean ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (POLKIT_IS_SUBJECT (subject), FALSE);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = call_sync_new ();
  polkit_authority_revoke_temporary_authorizations (authority, subject, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_revoke_temporary_authorizations_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_revoke_temporary_authorization_by_id:
 * @authority: A #PolkitAuthority.
 * @id: The opaque identifier for the temporary authorization.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied.
 * @user_data: The data to pass to @callback.
 *
 * Asynchronously revoke a temporary authorization.
 *
 * When the operation is finished, @callback will be invoked in the
 * <link linkend="g-main-context-push-thread-default">thread-default
 * main loop</link> of the thread you are calling this method
 * from. You can then call
 * polkit_authority_revoke_temporary_authorization_by_id_finish() to
 * get the result of the operation.
 */
void
polkit_authority_revoke_temporary_authorization_by_id (PolkitAuthority     *authority,
                                                       const gchar         *id,
                                                       GCancellable        *cancellable,
                                                       GAsyncReadyCallback  callback,
                                                       gpointer             user_data)
{
  g_return_if_fail (POLKIT_IS_AUTHORITY (authority));
  g_return_if_fail (id != NULL);
  g_return_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable));

  g_dbus_proxy_call (authority->proxy,
                     "RevokeTemporaryAuthorizationById",
                     g_variant_new ("(s)",
                                    id),
                     G_DBUS_CALL_FLAGS_NONE,
                     -1,
                     cancellable,
                     generic_async_cb,
                     g_simple_async_result_new (G_OBJECT (authority),
                                                callback,
                                                user_data,
                                                polkit_authority_revoke_temporary_authorization_by_id));
}

/**
 * polkit_authority_revoke_temporary_authorization_by_id_finish:
 * @authority: A #PolkitAuthority.
 * @res: A #GAsyncResult obtained from the callback.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Finishes revoking a temporary authorization by id.
 *
 * Returns: %TRUE if the temporary authorization was revoked, %FALSE if error is set.
 **/
gboolean
polkit_authority_revoke_temporary_authorization_by_id_finish (PolkitAuthority *authority,
                                                              GAsyncResult    *res,
                                                              GError         **error)
{
  gboolean ret;
  GVariant *value;
  GAsyncResult *_res;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (res), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  ret = FALSE;

  g_warn_if_fail (g_simple_async_result_get_source_tag (G_SIMPLE_ASYNC_RESULT (res)) == polkit_authority_revoke_temporary_authorization_by_id);
  _res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res)));

  value = g_dbus_proxy_call_finish (authority->proxy, _res, error);
  if (value == NULL)
    goto out;
  ret = TRUE;
  g_variant_unref (value);

 out:
  return ret;
}

/**
 * polkit_authority_revoke_temporary_authorization_by_id_sync:
 * @authority: A #PolkitAuthority.
 * @id: The opaque identifier for the temporary authorization.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Synchronously revokes a temporary authorization.
 *
 * The calling thread is blocked until a reply is received. See
 * polkit_authority_revoke_temporary_authorization_by_id() for the
 * asynchronous version.
 *
 * Returns: %TRUE if the temporary authorization was revoked, %FALSE if error is set.
 **/
gboolean
polkit_authority_revoke_temporary_authorization_by_id_sync (PolkitAuthority     *authority,
                                                            const gchar         *id,
                                                            GCancellable        *cancellable,
                                                            GError             **error)
{
  gboolean ret;
  CallSyncData *data;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), FALSE);
  g_return_val_if_fail (id != NULL, FALSE);
  g_return_val_if_fail (cancellable == NULL || G_IS_CANCELLABLE (cancellable), FALSE);
  g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

  data = call_sync_new ();
  polkit_authority_revoke_temporary_authorization_by_id (authority, id, cancellable, call_sync_cb, data);
  call_sync_block (data);
  ret = polkit_authority_revoke_temporary_authorization_by_id_finish (authority, data->res, error);
  call_sync_free (data);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

/**
 * polkit_authority_get_owner:
 * @authority: A #PolkitAuthority.
 *
 * The unique name on the system message bus of the owner of the name
 * <literal>org.freedesktop.PolicyKit1</literal> or %NULL if no-one
 * currently owns the name. You may connect to the #GObject::notify
 * signal to track changes to the #PolkitAuthority:owner property.
 *
 * Returns: (allow-none): %NULL or a string that should be freed with g_free().
 **/
gchar *
polkit_authority_get_owner (PolkitAuthority *authority)
{
  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  return g_dbus_proxy_get_name_owner (authority->proxy);
}

/**
 * polkit_authority_get_backend_name:
 * @authority: A #PolkitAuthority.
 *
 * Gets the name of the authority backend.
 *
 * Returns: The name of the backend.
 */
const gchar *
polkit_authority_get_backend_name (PolkitAuthority *authority)
{
  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  if (authority->name == NULL)
    {
      GVariant *value;
      value = g_dbus_proxy_get_cached_property (authority->proxy, "BackendName");
      authority->name = g_variant_dup_string (value, NULL);
      g_variant_unref (value);
    }
  return authority->name;
}

/**
 * polkit_authority_get_backend_version:
 * @authority: A #PolkitAuthority.
 *
 * Gets the version of the authority backend.
 *
 * Returns: The version string for the backend.
 */
const gchar *
polkit_authority_get_backend_version (PolkitAuthority *authority)
{
  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), NULL);
  if (authority->version == NULL)
    {
      GVariant *value;
      value = g_dbus_proxy_get_cached_property (authority->proxy, "BackendVersion");
      authority->version = g_variant_dup_string (value, NULL);
      g_variant_unref (value);
    }
  return authority->version;
}

/**
 * polkit_authority_get_backend_features:
 * @authority: A #PolkitAuthority.
 *
 * Gets the features supported by the authority backend.
 *
 * Returns: Flags from #PolkitAuthorityFeatures.
 */
PolkitAuthorityFeatures
polkit_authority_get_backend_features (PolkitAuthority *authority)
{
  PolkitAuthorityFeatures ret;
  GVariant *value;

  g_return_val_if_fail (POLKIT_IS_AUTHORITY (authority), 0);

  value = g_dbus_proxy_get_cached_property (authority->proxy, "BackendFeatures");
  ret = (PolkitAuthorityFeatures) g_variant_get_uint32 (value);
  g_variant_unref (value);

  return ret;
}

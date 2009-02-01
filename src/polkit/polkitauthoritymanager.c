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

#include "polkitauthoritymanager.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitauthoritymanager
 * @title: PolkitAuthorityManager
 * @short_description: Authority Manager
 *
 * Checking claims.
 */

struct _PolkitAuthorityManager
{
  GObject parent_instance;

  EggDBusConnection *system_bus;
  EggDBusObjectProxy *authority_manager_object_proxy;

  _PolkitAuthorityManager *real;
};

struct _PolkitAuthorityManagerClass
{
  GObjectClass parent_class;

};

/* TODO: locking */

static PolkitAuthorityManager *the_authority_manager = NULL;

G_DEFINE_TYPE (PolkitAuthorityManager, polkit_authority_manager, G_TYPE_OBJECT);


static void
polkit_authority_manager_init (PolkitAuthorityManager *authority_manager)
{
  authority_manager->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  authority_manager->authority_manager_object_proxy = egg_dbus_connection_get_object_proxy (authority_manager->system_bus,
                                                                            "org.freedesktop.PolicyKit1",
                                                                            "/org/freedesktop/PolicyKit1/Authority");

  authority_manager->real = _POLKIT_QUERY_INTERFACE_AUTHORITY_MANAGER (authority_manager->authority_manager_object_proxy);
}

static void
polkit_authority_manager_finalize (GObject *object)
{
  PolkitAuthorityManager *authority_manager;

  authority_manager = POLKIT_AUTHORITY_MANAGER (object);

  g_object_unref (authority_manager->authority_manager_object_proxy);
  g_object_unref (authority_manager->system_bus);

  the_authority_manager = NULL;

  if (G_OBJECT_CLASS (polkit_authority_manager_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_authority_manager_parent_class)->finalize (object);
}

static void
polkit_authority_manager_class_init (PolkitAuthorityManagerClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_authority_manager_finalize;

}

PolkitAuthorityManager *
polkit_authority_manager_get (void)
{
  if (the_authority_manager != NULL)
    goto out;

  the_authority_manager = POLKIT_AUTHORITY_MANAGER (g_object_new (POLKIT_TYPE_AUTHORITY_MANAGER, NULL));

 out:
  return the_authority_manager;
}

static void
generic_cb (GObject      *source_obj,
            GAsyncResult *res,
            gpointer      user_data)
{
  GAsyncResult **target_res = user_data;

  *target_res = g_object_ref (res);
}

static void
generic_async_cb (GObject      *source_obj,
                  GAsyncResult *res,
                  gpointer      user_data)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (user_data);

  g_simple_async_result_set_op_res_gpointer (simple, g_object_ref (res), g_object_unref);
  g_simple_async_result_complete (simple);
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_manager_enumerate_users_async (PolkitAuthorityManager *authority_manager,
                                                GCancellable           *cancellable,
                                                GAsyncReadyCallback     callback,
                                                gpointer                user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (authority_manager),
                                      callback,
                                      user_data,
                                      polkit_authority_manager_enumerate_users_async);

  call_id = _polkit_authority_manager_enumerate_users (authority_manager->real,
                                                       EGG_DBUS_CALL_FLAGS_NONE,
                                                       cancellable,
                                                       generic_async_cb,
                                                       simple);

  return call_id;
}

void
polkit_authority_manager_enumerate_users (PolkitAuthorityManager     *authority_manager,
                                          GCancellable        *cancellable,
                                          GAsyncReadyCallback  callback,
                                          gpointer             user_data)
{
  polkit_authority_manager_enumerate_users_async (authority_manager, cancellable, callback, user_data);
}

GList *
polkit_authority_manager_enumerate_users_finish (PolkitAuthorityManager *authority_manager,
                                                 GAsyncResult           *res,
                                                 GError               **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_manager_enumerate_users_async);

  result = NULL;

  if (!_polkit_authority_manager_enumerate_users_finish (authority_manager->real,
                                                         &array_seq,
                                                         real_res,
                                                         error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitIdentity *real_identity;

      real_identity = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_identity_new_for_real (real_identity));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  g_object_unref (real_res);
  return result;
}

GList *
polkit_authority_manager_enumerate_users_sync (PolkitAuthorityManager *authority_manager,
                                               GCancellable           *cancellable,
                                               GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_manager_enumerate_users_async (authority_manager, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority_manager->system_bus, call_id);

  result = polkit_authority_manager_enumerate_users_finish (authority_manager, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_manager_enumerate_groups_async (PolkitAuthorityManager     *authority_manager,
                                                 GCancellable               *cancellable,
                                                 GAsyncReadyCallback         callback,
                                                 gpointer                    user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (authority_manager),
                                      callback,
                                      user_data,
                                      polkit_authority_manager_enumerate_groups_async);

  call_id = _polkit_authority_manager_enumerate_groups (authority_manager->real,
                                                        EGG_DBUS_CALL_FLAGS_NONE,
                                                        cancellable,
                                                        generic_async_cb,
                                                        simple);

  return call_id;
}

void
polkit_authority_manager_enumerate_groups (PolkitAuthorityManager     *authority_manager,
                                           GCancellable               *cancellable,
                                           GAsyncReadyCallback         callback,
                                           gpointer                    user_data)
{
  polkit_authority_manager_enumerate_groups_async (authority_manager, cancellable, callback, user_data);
}

GList *
polkit_authority_manager_enumerate_groups_finish (PolkitAuthorityManager *authority_manager,
                                                  GAsyncResult            *res,
                                                  GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_manager_enumerate_groups_async);

  result = NULL;

  if (!_polkit_authority_manager_enumerate_groups_finish (authority_manager->real,
                                                  &array_seq,
                                                  real_res,
                                                  error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitIdentity *real_identity;

      real_identity = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_identity_new_for_real (real_identity));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  g_object_unref (real_res);
  return result;
}

GList *
polkit_authority_manager_enumerate_groups_sync (PolkitAuthorityManager *authority_manager,
                                                GCancellable           *cancellable,
                                                GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_manager_enumerate_groups_async (authority_manager, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority_manager->system_bus, call_id);

  result = polkit_authority_manager_enumerate_groups_finish (authority_manager, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_manager_enumerate_authorizations_async (PolkitAuthorityManager *authority_manager,
                                                         PolkitIdentity         *identity,
                                                         GCancellable           *cancellable,
                                                         GAsyncReadyCallback     callback,
                                                         gpointer                user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (authority_manager),
                                      callback,
                                      user_data,
                                      polkit_authority_manager_enumerate_authorizations_async);

  real_identity = polkit_identity_get_real (identity);

  call_id = _polkit_authority_manager_enumerate_authorizations (authority_manager->real,
                                                                EGG_DBUS_CALL_FLAGS_NONE,
                                                                real_identity,
                                                                cancellable,
                                                                generic_async_cb,
                                                                simple);

  g_object_unref (real_identity);

  return call_id;
}

void
polkit_authority_manager_enumerate_authorizations (PolkitAuthorityManager  *authority_manager,
                                                   PolkitIdentity          *identity,
                                                   GCancellable            *cancellable,
                                                   GAsyncReadyCallback      callback,
                                                   gpointer                 user_data)
{
  polkit_authority_manager_enumerate_authorizations_async (authority_manager,
                                                           identity,
                                                           cancellable,
                                                           callback,
                                                           user_data);
}

GList *
polkit_authority_manager_enumerate_authorizations_finish (PolkitAuthorityManager *authority_manager,
                                                          GAsyncResult           *res,
                                                          GError                **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_manager_enumerate_authorizations_async);

  result = NULL;

  if (!_polkit_authority_manager_enumerate_authorizations_finish (authority_manager->real,
                                                                  &array_seq,
                                                                  real_res,
                                                                  error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitAuthorization *real_authorization;

      real_authorization = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_authorization_new_for_real (real_authorization));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  g_object_unref (real_res);
  return result;
}


GList *
polkit_authority_manager_enumerate_authorizations_sync (PolkitAuthorityManager *authority_manager,
                                                        PolkitIdentity         *identity,
                                                        GCancellable           *cancellable,
                                                        GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_manager_enumerate_authorizations_async (authority_manager,
                                                                     identity,
                                                                     cancellable,
                                                                     generic_cb,
                                                                     &res);

  egg_dbus_connection_pending_call_block (authority_manager->system_bus, call_id);

  result = polkit_authority_manager_enumerate_authorizations_finish (authority_manager, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_manager_add_authorization_async (PolkitAuthorityManager  *authority_manager,
                                                  PolkitIdentity          *identity,
                                                  PolkitAuthorization     *authorization,
                                                  GCancellable            *cancellable,
                                                  GAsyncReadyCallback      callback,
                                                  gpointer                 user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitAuthorization *real_authorization;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (authority_manager),
                                      callback,
                                      user_data,
                                      polkit_authority_manager_add_authorization_async);

  real_identity = polkit_identity_get_real (identity);
  real_authorization = polkit_authorization_get_real (authorization);

  call_id = _polkit_authority_manager_add_authorization (authority_manager->real,
                                                         EGG_DBUS_CALL_FLAGS_NONE,
                                                         real_identity,
                                                         real_authorization,
                                                         cancellable,
                                                         generic_async_cb,
                                                         simple);

  g_object_unref (real_authorization);
  g_object_unref (real_identity);

  return call_id;
}

void
polkit_authority_manager_add_authorization (PolkitAuthorityManager *authority_manager,
                                            PolkitIdentity         *identity,
                                            PolkitAuthorization    *authorization,
                                            GCancellable           *cancellable,
                                            GAsyncReadyCallback     callback,
                                            gpointer                user_data)
{
  polkit_authority_manager_add_authorization_async (authority_manager,
                                                    identity,
                                                    authorization,
                                                    cancellable,
                                                    callback,
                                                    user_data);
}

gboolean
polkit_authority_manager_add_authorization_finish (PolkitAuthorityManager *authority_manager,
                                                   GAsyncResult           *res,
                                                   GError                **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_manager_add_authorization_async);

  ret = _polkit_authority_manager_add_authorization_finish (authority_manager->real,
                                                            real_res,
                                                            error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}


gboolean
polkit_authority_manager_add_authorization_sync (PolkitAuthorityManager *authority_manager,
                                                 PolkitIdentity         *identity,
                                                 PolkitAuthorization    *authorization,
                                                 GCancellable           *cancellable,
                                                 GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_authority_manager_add_authorization_async (authority_manager,
                                                              identity,
                                                              authorization,
                                                              cancellable,
                                                              generic_cb,
                                                              &res);

  egg_dbus_connection_pending_call_block (authority_manager->system_bus, call_id);

  ret = polkit_authority_manager_add_authorization_finish (authority_manager, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_manager_remove_authorization_async (PolkitAuthorityManager *authority_manager,
                                                     PolkitIdentity         *identity,
                                                     PolkitAuthorization    *authorization,
                                                     GCancellable           *cancellable,
                                                     GAsyncReadyCallback     callback,
                                                     gpointer                user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitAuthorization *real_authorization;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (authority_manager),
                                      callback,
                                      user_data,
                                      polkit_authority_manager_remove_authorization_async);

  real_identity = polkit_identity_get_real (identity);
  real_authorization = polkit_authorization_get_real (authorization);

  call_id = _polkit_authority_manager_remove_authorization (authority_manager->real,
                                                            EGG_DBUS_CALL_FLAGS_NONE,
                                                            real_identity,
                                                            real_authorization,
                                                            cancellable,
                                                            generic_async_cb,
                                                            simple);

  g_object_unref (real_authorization);
  g_object_unref (real_identity);

  return call_id;
}

void
polkit_authority_manager_remove_authorization (PolkitAuthorityManager  *authority_manager,
                                               PolkitIdentity          *identity,
                                               PolkitAuthorization     *authorization,
                                               GCancellable            *cancellable,
                                               GAsyncReadyCallback      callback,
                                               gpointer                 user_data)
{
  polkit_authority_manager_remove_authorization_async (authority_manager,
                                                       identity,
                                                       authorization,
                                                       cancellable,
                                                       callback,
                                                       user_data);
}

gboolean
polkit_authority_manager_remove_authorization_finish (PolkitAuthorityManager  *authority_manager,
                                                      GAsyncResult            *res,
                                                      GError                 **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_authority_manager_remove_authorization_async);

  ret = _polkit_authority_manager_remove_authorization_finish (authority_manager->real,
                                                               real_res,
                                                               error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}


gboolean
polkit_authority_manager_remove_authorization_sync (PolkitAuthorityManager *authority_manager,
                                                    PolkitIdentity         *identity,
                                                    PolkitAuthorization    *authorization,
                                                    GCancellable           *cancellable,
                                                    GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_authority_manager_remove_authorization_async (authority_manager,
                                                                 identity,
                                                                 authorization,
                                                                 cancellable,
                                                                 generic_cb,
                                                                 &res);

  egg_dbus_connection_pending_call_block (authority_manager->system_bus, call_id);

  ret = polkit_authority_manager_remove_authorization_finish (authority_manager, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

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

#include "polkitlocalauthority.h"

#include "polkitprivate.h"
#include "polkitlocalprivate.h"

/**
 * SECTION:polkitlocalauthority
 * @title: PolkitLocalAuthority
 * @short_description: Manage the Local Authority
 * @stability: Unstable
 *
 * Manage authorizations.
 *
 * To use this unstable API you need to define the symbol
 * <literal>POLKIT_LOCAL_I_KNOW_API_IS_SUBJECT_TO_CHANGE</literal>.
 */

struct _PolkitLocalAuthority
{
  GObject parent_instance;

  EggDBusConnection *system_bus;
  EggDBusObjectProxy *local_authority_object_proxy;

  _PolkitLocalAuthority *real;
};

struct _PolkitLocalAuthorityClass
{
  GObjectClass parent_class;

};

/* TODO: locking */

static PolkitLocalAuthority *the_local_authority = NULL;

G_DEFINE_TYPE (PolkitLocalAuthority, polkit_local_authority, G_TYPE_OBJECT);


static void
polkit_local_authority_init (PolkitLocalAuthority *local_authority)
{
  local_authority->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  local_authority->local_authority_object_proxy = egg_dbus_connection_get_object_proxy (local_authority->system_bus,
                                                                            "org.freedesktop.PolicyKit1",
                                                                            "/org/freedesktop/PolicyKit1/Authority");

  local_authority->real = _POLKIT_QUERY_INTERFACE_LOCAL_AUTHORITY (local_authority->local_authority_object_proxy);
}

static void
polkit_local_authority_finalize (GObject *object)
{
  PolkitLocalAuthority *local_authority;

  local_authority = POLKIT_LOCAL_AUTHORITY (object);

  g_object_unref (local_authority->local_authority_object_proxy);
  g_object_unref (local_authority->system_bus);

  the_local_authority = NULL;

  if (G_OBJECT_CLASS (polkit_local_authority_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_local_authority_parent_class)->finalize (object);
}

static void
polkit_local_authority_class_init (PolkitLocalAuthorityClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_local_authority_finalize;

}

PolkitLocalAuthority *
polkit_local_authority_get (void)
{
  if (the_local_authority != NULL)
    goto out;

  the_local_authority = POLKIT_LOCAL_AUTHORITY (g_object_new (POLKIT_TYPE_LOCAL_AUTHORITY, NULL));

 out:
  return the_local_authority;
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
polkit_local_authority_enumerate_users_async (PolkitLocalAuthority *local_authority,
                                                GCancellable           *cancellable,
                                                GAsyncReadyCallback     callback,
                                                gpointer                user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (local_authority),
                                      callback,
                                      user_data,
                                      polkit_local_authority_enumerate_users_async);

  call_id = _polkit_local_authority_enumerate_users (local_authority->real,
                                                       EGG_DBUS_CALL_FLAGS_NONE,
                                                       cancellable,
                                                       generic_async_cb,
                                                       simple);

  return call_id;
}

void
polkit_local_authority_enumerate_users (PolkitLocalAuthority     *local_authority,
                                          GCancellable        *cancellable,
                                          GAsyncReadyCallback  callback,
                                          gpointer             user_data)
{
  polkit_local_authority_enumerate_users_async (local_authority, cancellable, callback, user_data);
}

GList *
polkit_local_authority_enumerate_users_finish (PolkitLocalAuthority *local_authority,
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

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_local_authority_enumerate_users_async);

  result = NULL;

  if (!_polkit_local_authority_enumerate_users_finish (local_authority->real,
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
polkit_local_authority_enumerate_users_sync (PolkitLocalAuthority *local_authority,
                                               GCancellable           *cancellable,
                                               GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_local_authority_enumerate_users_async (local_authority, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (local_authority->system_bus, call_id);

  result = polkit_local_authority_enumerate_users_finish (local_authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_local_authority_enumerate_groups_async (PolkitLocalAuthority     *local_authority,
                                                 GCancellable               *cancellable,
                                                 GAsyncReadyCallback         callback,
                                                 gpointer                    user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;

  simple = g_simple_async_result_new (G_OBJECT (local_authority),
                                      callback,
                                      user_data,
                                      polkit_local_authority_enumerate_groups_async);

  call_id = _polkit_local_authority_enumerate_groups (local_authority->real,
                                                        EGG_DBUS_CALL_FLAGS_NONE,
                                                        cancellable,
                                                        generic_async_cb,
                                                        simple);

  return call_id;
}

void
polkit_local_authority_enumerate_groups (PolkitLocalAuthority     *local_authority,
                                           GCancellable               *cancellable,
                                           GAsyncReadyCallback         callback,
                                           gpointer                    user_data)
{
  polkit_local_authority_enumerate_groups_async (local_authority, cancellable, callback, user_data);
}

GList *
polkit_local_authority_enumerate_groups_finish (PolkitLocalAuthority *local_authority,
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

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_local_authority_enumerate_groups_async);

  result = NULL;

  if (!_polkit_local_authority_enumerate_groups_finish (local_authority->real,
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
polkit_local_authority_enumerate_groups_sync (PolkitLocalAuthority *local_authority,
                                                GCancellable           *cancellable,
                                                GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_local_authority_enumerate_groups_async (local_authority, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (local_authority->system_bus, call_id);

  result = polkit_local_authority_enumerate_groups_finish (local_authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_local_authority_enumerate_authorizations_async (PolkitLocalAuthority *local_authority,
                                                         PolkitIdentity         *identity,
                                                         GCancellable           *cancellable,
                                                         GAsyncReadyCallback     callback,
                                                         gpointer                user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (local_authority),
                                      callback,
                                      user_data,
                                      polkit_local_authority_enumerate_authorizations_async);

  real_identity = polkit_identity_get_real (identity);

  call_id = _polkit_local_authority_enumerate_authorizations (local_authority->real,
                                                                EGG_DBUS_CALL_FLAGS_NONE,
                                                                real_identity,
                                                                cancellable,
                                                                generic_async_cb,
                                                                simple);

  g_object_unref (real_identity);

  return call_id;
}

void
polkit_local_authority_enumerate_authorizations (PolkitLocalAuthority  *local_authority,
                                                   PolkitIdentity          *identity,
                                                   GCancellable            *cancellable,
                                                   GAsyncReadyCallback      callback,
                                                   gpointer                 user_data)
{
  polkit_local_authority_enumerate_authorizations_async (local_authority,
                                                           identity,
                                                           cancellable,
                                                           callback,
                                                           user_data);
}

GList *
polkit_local_authority_enumerate_authorizations_finish (PolkitLocalAuthority *local_authority,
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

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_local_authority_enumerate_authorizations_async);

  result = NULL;

  if (!_polkit_local_authority_enumerate_authorizations_finish (local_authority->real,
                                                                  &array_seq,
                                                                  real_res,
                                                                  error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitLocalAuthorization *real_authorization;

      real_authorization = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_local_authorization_new_for_real (real_authorization));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  g_object_unref (real_res);
  return result;
}


GList *
polkit_local_authority_enumerate_authorizations_sync (PolkitLocalAuthority *local_authority,
                                                        PolkitIdentity         *identity,
                                                        GCancellable           *cancellable,
                                                        GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_local_authority_enumerate_authorizations_async (local_authority,
                                                                     identity,
                                                                     cancellable,
                                                                     generic_cb,
                                                                     &res);

  egg_dbus_connection_pending_call_block (local_authority->system_bus, call_id);

  result = polkit_local_authority_enumerate_authorizations_finish (local_authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_local_authority_add_authorization_async (PolkitLocalAuthority  *local_authority,
                                                  PolkitIdentity          *identity,
                                                  PolkitLocalAuthorization     *authorization,
                                                  GCancellable            *cancellable,
                                                  GAsyncReadyCallback      callback,
                                                  gpointer                 user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitLocalAuthorization *real_authorization;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (local_authority),
                                      callback,
                                      user_data,
                                      polkit_local_authority_add_authorization_async);

  real_identity = polkit_identity_get_real (identity);
  real_authorization = polkit_local_authorization_get_real (authorization);

  call_id = _polkit_local_authority_add_authorization (local_authority->real,
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
polkit_local_authority_add_authorization (PolkitLocalAuthority *local_authority,
                                            PolkitIdentity         *identity,
                                            PolkitLocalAuthorization    *authorization,
                                            GCancellable           *cancellable,
                                            GAsyncReadyCallback     callback,
                                            gpointer                user_data)
{
  polkit_local_authority_add_authorization_async (local_authority,
                                                    identity,
                                                    authorization,
                                                    cancellable,
                                                    callback,
                                                    user_data);
}

gboolean
polkit_local_authority_add_authorization_finish (PolkitLocalAuthority *local_authority,
                                                   GAsyncResult           *res,
                                                   GError                **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_local_authority_add_authorization_async);

  ret = _polkit_local_authority_add_authorization_finish (local_authority->real,
                                                            real_res,
                                                            error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}


gboolean
polkit_local_authority_add_authorization_sync (PolkitLocalAuthority *local_authority,
                                                 PolkitIdentity         *identity,
                                                 PolkitLocalAuthorization    *authorization,
                                                 GCancellable           *cancellable,
                                                 GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_local_authority_add_authorization_async (local_authority,
                                                              identity,
                                                              authorization,
                                                              cancellable,
                                                              generic_cb,
                                                              &res);

  egg_dbus_connection_pending_call_block (local_authority->system_bus, call_id);

  ret = polkit_local_authority_add_authorization_finish (local_authority, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_local_authority_remove_authorization_async (PolkitLocalAuthority *local_authority,
                                                     PolkitIdentity         *identity,
                                                     PolkitLocalAuthorization    *authorization,
                                                     GCancellable           *cancellable,
                                                     GAsyncReadyCallback     callback,
                                                     gpointer                user_data)
{
  guint call_id;
  GSimpleAsyncResult *simple;
  _PolkitLocalAuthorization *real_authorization;
  _PolkitIdentity *real_identity;

  simple = g_simple_async_result_new (G_OBJECT (local_authority),
                                      callback,
                                      user_data,
                                      polkit_local_authority_remove_authorization_async);

  real_identity = polkit_identity_get_real (identity);
  real_authorization = polkit_local_authorization_get_real (authorization);

  call_id = _polkit_local_authority_remove_authorization (local_authority->real,
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
polkit_local_authority_remove_authorization (PolkitLocalAuthority  *local_authority,
                                               PolkitIdentity          *identity,
                                               PolkitLocalAuthorization     *authorization,
                                               GCancellable            *cancellable,
                                               GAsyncReadyCallback      callback,
                                               gpointer                 user_data)
{
  polkit_local_authority_remove_authorization_async (local_authority,
                                                       identity,
                                                       authorization,
                                                       cancellable,
                                                       callback,
                                                       user_data);
}

gboolean
polkit_local_authority_remove_authorization_finish (PolkitLocalAuthority  *local_authority,
                                                      GAsyncResult            *res,
                                                      GError                 **error)
{
  GSimpleAsyncResult *simple;
  GAsyncResult *real_res;
  gboolean ret;

  simple = G_SIMPLE_ASYNC_RESULT (res);
  real_res = G_ASYNC_RESULT (g_simple_async_result_get_op_res_gpointer (simple));

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_local_authority_remove_authorization_async);

  ret = _polkit_local_authority_remove_authorization_finish (local_authority->real,
                                                               real_res,
                                                               error);

  if (!ret)
    goto out;

 out:
  g_object_unref (real_res);
  return ret;
}


gboolean
polkit_local_authority_remove_authorization_sync (PolkitLocalAuthority *local_authority,
                                                    PolkitIdentity         *identity,
                                                    PolkitLocalAuthorization    *authorization,
                                                    GCancellable           *cancellable,
                                                    GError                **error)
{
  guint call_id;
  GAsyncResult *res;
  gboolean ret;

  call_id = polkit_local_authority_remove_authorization_async (local_authority,
                                                                 identity,
                                                                 authorization,
                                                                 cancellable,
                                                                 generic_cb,
                                                                 &res);

  egg_dbus_connection_pending_call_block (local_authority->system_bus, call_id);

  ret = polkit_local_authority_remove_authorization_finish (local_authority, res, error);

  g_object_unref (res);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

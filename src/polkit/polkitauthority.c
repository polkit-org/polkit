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
#include "polkitauthority.h"

#include "polkitprivate.h"

/**
 * SECTION:polkitauthority
 * @title: PolkitAuthority
 * @short_description: Authority
 *
 * Checking claims.
 */

struct _PolkitAuthority
{
  GObject parent_instance;

  EggDBusConnection *system_bus;
  EggDBusObjectProxy *authority_object_proxy;

  _PolkitAuthority *real;
};

struct _PolkitAuthorityClass
{
  GObjectClass parent_class;

};

/* TODO: locking */

static PolkitAuthority *the_authority = NULL;

G_DEFINE_TYPE (PolkitAuthority, polkit_authority, G_TYPE_OBJECT);

static void
polkit_authority_init (PolkitAuthority *authority)
{
  authority->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  authority->authority_object_proxy = egg_dbus_connection_get_object_proxy (authority->system_bus,
                                                                            "org.freedesktop.PolicyKit1",
                                                                            "/org/freedesktop/PolicyKit1/Authority");

  authority->real = _POLKIT_QUERY_INTERFACE_AUTHORITY (authority->authority_object_proxy);
}

static void
polkit_authority_finalize (GObject *object)
{
  PolkitAuthority *authority;

  authority = POLKIT_AUTHORITY (object);

  g_object_unref (authority->authority_object_proxy);
  g_object_unref (authority->system_bus);

  the_authority = NULL;

  if (G_OBJECT_CLASS (polkit_authority_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_authority_parent_class)->finalize (object);
}

static void
polkit_authority_class_init (PolkitAuthorityClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_authority_finalize;
}

PolkitAuthority *
polkit_authority_get (void)
{
  if (the_authority != NULL)
    goto out;

  the_authority = POLKIT_AUTHORITY (g_object_new (POLKIT_TYPE_AUTHORITY, NULL));

 out:
  return the_authority;
}

static void
generic_cb (GObject      *source_obj,
            GAsyncResult *res,
            gpointer      user_data)
{
  GAsyncResult **target_res = user_data;

  *target_res = g_object_ref (res);
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_enumerate_actions_async (PolkitAuthority     *authority,
                                          const gchar         *locale,
                                          GCancellable        *cancellable,
                                          GAsyncReadyCallback  callback,
                                          gpointer             user_data)
{
  guint call_id;

  call_id = _polkit_authority_enumerate_actions (authority->real,
                                                 EGG_DBUS_CALL_FLAGS_NONE,
                                                 locale,
                                                 cancellable,
                                                 callback,
                                                 user_data);

  return call_id;
}

void
polkit_authority_enumerate_actions (PolkitAuthority     *authority,
                                    const gchar         *locale,
                                    GCancellable        *cancellable,
                                    GAsyncReadyCallback  callback,
                                    gpointer             user_data)
{
  polkit_authority_enumerate_actions_async (authority, locale, cancellable, callback, user_data);
}

GList *
polkit_authority_enumerate_actions_finish (PolkitAuthority *authority,
                                           GAsyncResult    *res,
                                           GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;

  result = NULL;

  if (!_polkit_authority_enumerate_actions_finish (authority->real,
                                                   &array_seq,
                                                   res,
                                                   error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitActionDescription *real_ad;

      real_ad = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_action_description_new_for_real (real_ad));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  return result;
}


GList *
polkit_authority_enumerate_actions_sync (PolkitAuthority *authority,
                                         const gchar     *locale,
                                         GCancellable    *cancellable,
                                         GError         **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_enumerate_actions_async (authority, locale, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  result = polkit_authority_enumerate_actions_finish (authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_enumerate_users_async (PolkitAuthority     *authority,
                                        GCancellable        *cancellable,
                                        GAsyncReadyCallback  callback,
                                        gpointer             user_data)
{
  guint call_id;

  call_id = _polkit_authority_enumerate_users (authority->real,
                                               EGG_DBUS_CALL_FLAGS_NONE,
                                               cancellable,
                                               callback,
                                               user_data);

  return call_id;
}

void
polkit_authority_enumerate_users (PolkitAuthority     *authority,
                                  GCancellable        *cancellable,
                                  GAsyncReadyCallback  callback,
                                  gpointer             user_data)
{
  polkit_authority_enumerate_users_async (authority, cancellable, callback, user_data);
}

GList *
polkit_authority_enumerate_users_finish (PolkitAuthority *authority,
                                         GAsyncResult    *res,
                                         GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;

  result = NULL;

  if (!_polkit_authority_enumerate_users_finish (authority->real,
                                                 &array_seq,
                                                 res,
                                                 error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitSubject *real_subject;

      real_subject = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_subject_new_for_real (real_subject));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  return result;
}

GList *
polkit_authority_enumerate_users_sync (PolkitAuthority *authority,
                                       GCancellable    *cancellable,
                                       GError         **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_enumerate_users_async (authority, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  result = polkit_authority_enumerate_users_finish (authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_enumerate_groups_async (PolkitAuthority     *authority,
                                        GCancellable        *cancellable,
                                        GAsyncReadyCallback  callback,
                                        gpointer             user_data)
{
  guint call_id;

  call_id = _polkit_authority_enumerate_groups (authority->real,
                                                EGG_DBUS_CALL_FLAGS_NONE,
                                                cancellable,
                                                callback,
                                                user_data);

  return call_id;
}

void
polkit_authority_enumerate_groups (PolkitAuthority     *authority,
                                   GCancellable        *cancellable,
                                   GAsyncReadyCallback  callback,
                                   gpointer             user_data)
{
  polkit_authority_enumerate_groups_async (authority, cancellable, callback, user_data);
}

GList *
polkit_authority_enumerate_groups_finish (PolkitAuthority *authority,
                                          GAsyncResult    *res,
                                          GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;

  result = NULL;

  if (!_polkit_authority_enumerate_groups_finish (authority->real,
                                                  &array_seq,
                                                  res,
                                                  error))
    goto out;

  for (n = 0; n < array_seq->size; n++)
    {
      _PolkitSubject *real_subject;

      real_subject = array_seq->data.v_ptr[n];

      result = g_list_prepend (result, polkit_subject_new_for_real (real_subject));
    }

  result = g_list_reverse (result);

  g_object_unref (array_seq);

 out:
  return result;
}

GList *
polkit_authority_enumerate_groups_sync (PolkitAuthority *authority,
                                        GCancellable    *cancellable,
                                        GError         **error)
{
  guint call_id;
  GAsyncResult *res;
  GList *result;

  call_id = polkit_authority_enumerate_groups_async (authority, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  result = polkit_authority_enumerate_groups_finish (authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

static guint
polkit_authority_check_claim_async (PolkitAuthority          *authority,
                                    PolkitAuthorizationClaim *claim,
                                    GCancellable             *cancellable,
                                    GAsyncReadyCallback       callback,
                                    gpointer                  user_data)
{
  _PolkitAuthorizationClaim *real_claim;
  guint call_id;

  real_claim = polkit_authorization_claim_get_real (claim);

  call_id = _polkit_authority_check_claim (authority->real,
                                           EGG_DBUS_CALL_FLAGS_NONE,
                                           real_claim,
                                           cancellable,
                                           callback,
                                           user_data);

  g_object_unref (real_claim);

  return call_id;
}

void
polkit_authority_check_claim (PolkitAuthority          *authority,
                              PolkitAuthorizationClaim *claim,
                              GCancellable             *cancellable,
                              GAsyncReadyCallback       callback,
                              gpointer                  user_data)
{
  polkit_authority_check_claim_async (authority, claim, cancellable, callback, user_data);
}

PolkitAuthorizationResult
polkit_authority_check_claim_finish (PolkitAuthority          *authority,
                                     GAsyncResult             *res,
                                     GError                  **error)
{
  _PolkitAuthorizationResult result;
  EggDBusHashMap *result_attributes;

  result = _POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

  if (!_polkit_authority_check_claim_finish (authority->real,
                                             &result,
                                             &result_attributes,
                                             res,
                                             error))
    goto out;

  /* TODO: pass these back */
  if (result_attributes != NULL)
    g_object_unref (result_attributes);

 out:

  return result;
}

PolkitAuthorizationResult
polkit_authority_check_claim_sync (PolkitAuthority          *authority,
                                   PolkitAuthorizationClaim *claim,
                                   GCancellable             *cancellable,
                                   GError                  **error)
{
  guint call_id;
  GAsyncResult *res;
  PolkitAuthorizationResult result;

  call_id = polkit_authority_check_claim_async (authority, claim, cancellable, generic_cb, &res);

  egg_dbus_connection_pending_call_block (authority->system_bus, call_id);

  result = polkit_authority_check_claim_finish (authority, res, error);

  g_object_unref (res);

  return result;
}

/* ---------------------------------------------------------------------------------------------------- */

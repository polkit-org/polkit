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
  EggDBusConnection *system_bus;

  system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  authority->authority_object_proxy = egg_dbus_connection_get_object_proxy (system_bus,
                                                                            "org.freedesktop.PolicyKit1",
                                                                            "/org/freedesktop/PolicyKit1/Authority");

  authority->real = _POLKIT_QUERY_INTERFACE_AUTHORITY (authority->authority_object_proxy);

  g_object_unref (system_bus);
}

static void
polkit_authority_finalize (GObject *object)
{
  PolkitAuthority *authority;

  authority = POLKIT_AUTHORITY (object);

  g_object_unref (authority->authority_object_proxy);

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

GList *
polkit_authority_enumerate_actions_sync (PolkitAuthority *authority,
                                         const gchar     *locale,
                                         GCancellable    *cancellable,
                                         GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;

  result = NULL;

  if (!_polkit_authority_enumerate_actions_sync (authority->real,
                                                 EGG_DBUS_CALL_FLAGS_NONE,
                                                 locale,
                                                 &array_seq,
                                                 cancellable,
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
polkit_authority_enumerate_users_sync (PolkitAuthority *authority,
                                       GCancellable    *cancellable,
                                       GError         **error)
{
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;

  result = NULL;

  if (!_polkit_authority_enumerate_users_sync (authority->real,
                                               EGG_DBUS_CALL_FLAGS_NONE,
                                               &array_seq,
                                               cancellable,
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
  EggDBusArraySeq *array_seq;
  GList *result;
  guint n;

  result = NULL;

  if (!_polkit_authority_enumerate_groups_sync (authority->real,
                                                EGG_DBUS_CALL_FLAGS_NONE,
                                                &array_seq,
                                                cancellable,
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

PolkitAuthorizationResult
polkit_authority_check_claim_sync (PolkitAuthority          *authority,
                                   PolkitAuthorizationClaim *claim,
                                   GCancellable             *cancellable,
                                   GError                  **error)
{
  _PolkitAuthorizationResult result;
  _PolkitAuthorizationClaim *real_claim;
  EggDBusHashMap *result_attributes;

  result = _POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;
  real_claim = NULL;

  real_claim = polkit_authorization_claim_get_real (claim);

  if (!_polkit_authority_check_claim_sync (authority->real,
                                           EGG_DBUS_CALL_FLAGS_NONE,
                                           real_claim,
                                           &result,
                                           &result_attributes,
                                           cancellable,
                                           error))
    goto out;

  /* TODO: pass these back */
  if (result_attributes != NULL)
    g_object_unref (result_attributes);

 out:
  if (real_claim != NULL)
    g_object_unref (real_claim);

  return result;
}


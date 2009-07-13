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

#include "polkitlocalauthorization.h"
#include "polkitprivate.h"
#include "polkitlocalprivate.h"

/**
 * SECTION:polkitlocalauthorization
 * @title: PolkitLocalAuthorization
 * @short_description: Local Authorization
 * @stability: Unstable
 *
 * Instances of this class represents authorizations for the local authority backend.
 *
 * To use this unstable API you need to define the symbol
 * <literal>POLKIT_LOCAL_I_KNOW_API_IS_SUBJECT_TO_CHANGE</literal>.
 */

struct _PolkitLocalAuthorization
{
  GObject parent_instance;

  _PolkitLocalAuthorization *real;

  PolkitSubject *subject;
};

struct _PolkitLocalAuthorizationClass
{
  GObjectClass parent_class;

};

G_DEFINE_TYPE (PolkitLocalAuthorization, polkit_local_authorization, G_TYPE_OBJECT);

static void
polkit_local_authorization_init (PolkitLocalAuthorization *local_authorization)
{
}

static void
polkit_local_authorization_finalize (GObject *object)
{
  PolkitLocalAuthorization *local_authorization;

  local_authorization = POLKIT_LOCAL_AUTHORIZATION (object);

  if (local_authorization->subject != NULL)
    g_object_unref (local_authorization->subject);

  g_object_unref (local_authorization->real);

  if (G_OBJECT_CLASS (polkit_local_authorization_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_local_authorization_parent_class)->finalize (object);
}

static void
polkit_local_authorization_class_init (PolkitLocalAuthorizationClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_local_authorization_finalize;
}

PolkitLocalAuthorization *
polkit_local_authorization_new (const gchar         *action_id,
                          PolkitSubject       *subject,
                          gboolean             is_negative)
{
  PolkitLocalAuthorization *local_authorization;
  _PolkitLocalAuthorization *real;
  _PolkitSubject *real_subject;

  real_subject = polkit_subject_get_real (subject);

  real = _polkit_local_authorization_new (action_id, real_subject, is_negative);

  g_object_unref (real_subject);

  local_authorization = polkit_local_authorization_new_for_real (real);

  g_object_unref (real);

  return local_authorization;
}

PolkitLocalAuthorization  *
polkit_local_authorization_new_for_real (_PolkitLocalAuthorization *real)
{
  PolkitLocalAuthorization *local_authorization;

  local_authorization = POLKIT_LOCAL_AUTHORIZATION (g_object_new (POLKIT_TYPE_LOCAL_AUTHORIZATION, NULL));

  local_authorization->real = g_object_ref (real);

  return local_authorization;
}

_PolkitLocalAuthorization *
polkit_local_authorization_get_real (PolkitLocalAuthorization  *local_authorization)
{
  return g_object_ref (local_authorization->real);
}

/* ---------------------------------------------------------------------------------------------------- */

const gchar *
polkit_local_authorization_get_action_id (PolkitLocalAuthorization *local_authorization)
{
  return _polkit_local_authorization_get_action_id (local_authorization->real);
}


PolkitSubject *
polkit_local_authorization_get_subject (PolkitLocalAuthorization *local_authorization)
{
  if (local_authorization->subject == NULL)
    local_authorization->subject = polkit_subject_new_for_real (_polkit_local_authorization_get_subject (local_authorization->real));

  return local_authorization->subject;
}

gboolean
polkit_local_authorization_get_is_negative (PolkitLocalAuthorization *local_authorization)
{
  return _polkit_local_authorization_get_is_negative (local_authorization->real);
}

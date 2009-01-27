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

#include "polkitauthorization.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitauthorization
 * @title: PolkitAuthorization
 * @short_description: Authorization
 *
 * This class represents an explicit authorization.
 */

struct _PolkitAuthorization
{
  GObject parent_instance;

  _PolkitAuthorization *real;

  PolkitSubject *subject;
};

struct _PolkitAuthorizationClass
{
  GObjectClass parent_class;

};

G_DEFINE_TYPE (PolkitAuthorization, polkit_authorization, G_TYPE_OBJECT);

static void
polkit_authorization_init (PolkitAuthorization *authorization)
{
}

static void
polkit_authorization_finalize (GObject *object)
{
  PolkitAuthorization *authorization;

  authorization = POLKIT_AUTHORIZATION (object);

  if (authorization->subject != NULL)
    g_object_unref (authorization->subject);

  g_object_unref (authorization->real);

  if (G_OBJECT_CLASS (polkit_authorization_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_authorization_parent_class)->finalize (object);
}

static void
polkit_authorization_class_init (PolkitAuthorizationClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_authorization_finalize;
}

PolkitAuthorization *
polkit_authorization_new (const gchar         *action_id,
                          PolkitSubject       *subject,
                          gboolean             is_negative)
{
  PolkitAuthorization *authorization;
  _PolkitAuthorization *real;
  _PolkitSubject *real_subject;

  real_subject = polkit_subject_get_real (subject);

  real = _polkit_authorization_new (action_id, real_subject, is_negative);

  g_object_unref (real_subject);

  authorization = polkit_authorization_new_for_real (real);

  g_object_unref (real);

  return authorization;
}

PolkitAuthorization  *
polkit_authorization_new_for_real (_PolkitAuthorization *real)
{
  PolkitAuthorization *authorization;

  authorization = POLKIT_AUTHORIZATION (g_object_new (POLKIT_TYPE_AUTHORIZATION, NULL));

  authorization->real = g_object_ref (real);

  return authorization;
}

_PolkitAuthorization *
polkit_authorization_get_real (PolkitAuthorization  *authorization)
{
  return g_object_ref (authorization->real);
}

/* ---------------------------------------------------------------------------------------------------- */

const gchar *
polkit_authorization_get_action_id (PolkitAuthorization *authorization)
{
  return _polkit_authorization_get_action_id (authorization->real);
}


PolkitSubject *
polkit_authorization_get_subject (PolkitAuthorization *authorization)
{
  if (authorization->subject == NULL)
    authorization->subject = polkit_subject_new_for_real (_polkit_authorization_get_subject (authorization->real));

  return authorization->subject;
}

gboolean
polkit_authorization_get_is_negative (PolkitAuthorization *authorization)
{
  return _polkit_authorization_get_is_negative (authorization->real);
}

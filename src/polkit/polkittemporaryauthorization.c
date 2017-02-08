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
#include "polkitimplicitauthorization.h"
#include "polkittemporaryauthorization.h"

#include "polkitprivate.h"

/**
 * SECTION:polkittemporaryauthorization
 * @title: PolkitTemporaryAuthorization
 * @short_description: Temporary Authorizations
 *
 * Object used to describe a temporary authorization.
 */

/**
 * PolkitTemporaryAuthorization:
 *
 * The #PolkitTemporaryAuthorization struct should not be accessed directly.
 */
struct _PolkitTemporaryAuthorization
{
  GObject parent_instance;

  gchar *id;
  gchar *action_id;
  PolkitSubject *subject;
  guint64 time_obtained;
  guint64 time_expires;
};

struct _PolkitTemporaryAuthorizationClass
{
  GObjectClass parent_class;
};

G_DEFINE_TYPE (PolkitTemporaryAuthorization, polkit_temporary_authorization, G_TYPE_OBJECT);

static void
polkit_temporary_authorization_init (PolkitTemporaryAuthorization *authorization)
{
}

static void
polkit_temporary_authorization_finalize (GObject *object)
{
  PolkitTemporaryAuthorization *authorization = POLKIT_TEMPORARY_AUTHORIZATION (object);

  g_free (authorization->id);
  g_free (authorization->action_id);
  g_object_unref (authorization->subject);

  if (G_OBJECT_CLASS (polkit_temporary_authorization_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_temporary_authorization_parent_class)->finalize (object);
}

static void
polkit_temporary_authorization_class_init (PolkitTemporaryAuthorizationClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_temporary_authorization_finalize;
}

PolkitTemporaryAuthorization *
polkit_temporary_authorization_new (const gchar                  *id,
                                    const gchar                  *action_id,
                                    PolkitSubject                *subject,
                                    guint64                       time_obtained,
                                    guint64                       time_expires)
{
  PolkitTemporaryAuthorization *authorization;
  authorization = POLKIT_TEMPORARY_AUTHORIZATION (g_object_new (POLKIT_TYPE_TEMPORARY_AUTHORIZATION, NULL));
  authorization->id = g_strdup (id);
  authorization->action_id = g_strdup (action_id);
  authorization->subject = g_object_ref (subject);
  authorization->time_obtained = time_obtained;
  authorization->time_expires = time_expires;
  return authorization;
}

/**
 * polkit_temporary_authorization_get_id:
 * @authorization: A #PolkitTemporaryAuthorization.
 *
 * Gets the opaque identifier for @authorization.
 *
 * Returns: A string owned by @authorization. Do not free.
 */
const gchar *
polkit_temporary_authorization_get_id (PolkitTemporaryAuthorization *authorization)
{
  g_return_val_if_fail (POLKIT_IS_TEMPORARY_AUTHORIZATION (authorization), NULL);
  return authorization->id;
}

/**
 * polkit_temporary_authorization_get_action_id:
 * @authorization: A #PolkitTemporaryAuthorization.
 *
 * Gets the action that @authorization is for.
 *
 * Returns: A string owned by @authorization. Do not free.
 **/
const gchar *
polkit_temporary_authorization_get_action_id (PolkitTemporaryAuthorization *authorization)
{
  g_return_val_if_fail (POLKIT_IS_TEMPORARY_AUTHORIZATION (authorization), NULL);
  return authorization->action_id;
}

/**
 * polkit_temporary_authorization_get_subject:
 * @authorization: A #PolkitTemporaryAuthorization.
 *
 * Gets the subject that @authorization is for.
 *
 * Returns: (transfer full): A #PolkitSubject, free with g_object_unref().
 **/
PolkitSubject *
polkit_temporary_authorization_get_subject (PolkitTemporaryAuthorization *authorization)
{
  g_return_val_if_fail (POLKIT_IS_TEMPORARY_AUTHORIZATION (authorization), NULL);
  return g_object_ref (authorization->subject);
}

/**
 * polkit_temporary_authorization_get_time_obtained:
 * @authorization: A #PolkitTemporaryAuthorization.
 *
 * Gets the time when @authorization was obtained.
 *
 * (Note that the PolicyKit daemon is using monotonic time internally
 * so the returned value may change if system time changes.)
 *
 * Returns: Seconds since the Epoch Jan 1. 1970, 0:00 UTC.
 **/
guint64
polkit_temporary_authorization_get_time_obtained (PolkitTemporaryAuthorization *authorization)
{
  g_return_val_if_fail (POLKIT_IS_TEMPORARY_AUTHORIZATION (authorization), 0);
  return authorization->time_obtained;
}

/**
 * polkit_temporary_authorization_get_time_expires:
 * @authorization: A #PolkitTemporaryAuthorization.
 *
 * Gets the time when @authorization will expire.
 *
 * (Note that the PolicyKit daemon is using monotonic time internally
 * so the returned value may change if system time changes.)
 *
 * Returns: Seconds since the Epoch Jan 1. 1970, 0:00 UTC.
 **/
guint64
polkit_temporary_authorization_get_time_expires (PolkitTemporaryAuthorization *authorization)
{
  g_return_val_if_fail (POLKIT_IS_TEMPORARY_AUTHORIZATION (authorization), 0);
  return authorization->time_expires;
}

PolkitTemporaryAuthorization *
polkit_temporary_authorization_new_for_gvariant (GVariant  *value,
                                                 GError   **error)
{
  PolkitTemporaryAuthorization *authorization;
  GVariant *subject_gvariant;

  authorization = POLKIT_TEMPORARY_AUTHORIZATION (g_object_new (POLKIT_TYPE_TEMPORARY_AUTHORIZATION, NULL));
  g_variant_get (value,
                 "(ss@(sa{sv})tt)",
                 &authorization->id,
                 &authorization->action_id,
                 &subject_gvariant,
                 &authorization->time_obtained,
                 &authorization->time_expires);
  authorization->subject = polkit_subject_new_for_gvariant (subject_gvariant, error);
  if (authorization->subject == NULL)
    {
      g_object_unref (authorization);
      authorization = NULL;
      goto out;
    }

 out:
  g_variant_unref (subject_gvariant);
  return authorization;
}

/* Note that this returns a floating value. */
GVariant *
polkit_temporary_authorization_to_gvariant (PolkitTemporaryAuthorization *authorization)
{
  return g_variant_new ("(ss@(sa{sv})tt)",
                        authorization->id,
                        authorization->action_id,
                        polkit_subject_to_gvariant (authorization->subject), /* A floating value */
                        authorization->time_obtained,
                        authorization->time_expires);
}


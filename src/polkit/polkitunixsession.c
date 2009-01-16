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
#include "polkitunixsession.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

/**
 * SECTION:polkitunixsession
 * @title: PolkitUnixSession
 * @short_description: Unix sessions
 *
 * Encapsulates a login session on UNIX.
 */

struct _PolkitUnixSession
{
  GObject parent_instance;

  gchar *session_id;
};

struct _PolkitUnixSessionClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_SESSION_ID,
};

static void subject_iface_init (PolkitSubjectIface *subject_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitUnixSession, polkit_unix_session, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_unix_session_init (PolkitUnixSession *unix_session)
{
}

static void
polkit_unix_session_get_property (GObject    *object,
                               guint       prop_id,
                               GValue     *value,
                               GParamSpec *pspec)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (object);

  switch (prop_id)
    {
    case PROP_SESSION_ID:
      g_value_set_string (value, session->session_id);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_session_set_property (GObject      *object,
                               guint         prop_id,
                               const GValue *value,
                               GParamSpec   *pspec)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (object);

  switch (prop_id)
    {
    case PROP_SESSION_ID:
      polkit_unix_session_set_session_id (session, g_value_get_string (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_session_class_init (PolkitUnixSessionClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_unix_session_get_property;
  gobject_class->set_property = polkit_unix_session_set_property;

  /**
   * PolkitUnixSession:session-id:
   *
   * The UNIX session id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_SESSION_ID,
                                   g_param_spec_string ("session-id",
                                                        "Session ID",
                                                        "The UNIX session ID",
                                                        NULL,
                                                        G_PARAM_CONSTRUCT |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

}

const gchar *
polkit_unix_session_get_session_id (PolkitUnixSession *session)
{
  return session->session_id;
}

void
polkit_unix_session_set_session_id (PolkitUnixSession *session,
                                    const gchar       *session_id)
{
  g_free (session->session_id);
  session->session_id = g_strdup (session_id);
}

PolkitSubject *
polkit_unix_session_new (const gchar *session_id)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_SESSION,
                                       "session-id", session_id,
                                       NULL));
}

static gboolean
polkit_unix_session_equal (PolkitSubject *a,
                           PolkitSubject *b)
{
  PolkitUnixSession *session_a;
  PolkitUnixSession *session_b;

  session_a = POLKIT_UNIX_SESSION (a);
  session_b = POLKIT_UNIX_SESSION (b);

  return g_strcmp0 (session_a->session_id, session_b->session_id) == 0;
}

static gchar *
polkit_unix_session_to_string (PolkitSubject *subject)
{
  PolkitUnixSession *session = POLKIT_UNIX_SESSION (subject);

  return g_strdup_printf ("unix-session:%s", session->session_id);
}

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->equal     = polkit_unix_session_equal;
  subject_iface->to_string = polkit_unix_session_to_string;
}

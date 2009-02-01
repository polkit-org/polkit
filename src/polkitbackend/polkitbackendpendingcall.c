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

#include "config.h"

#include <polkit/polkit.h>
#include "polkitbackendpendingcall.h"
#include "polkitbackendprivate.h"

typedef struct
{
  EggDBusMethodInvocation *method_invocation;
  PolkitSubject *inquirer;
} PolkitBackendPendingCallPrivate;

G_DEFINE_TYPE (PolkitBackendPendingCall, polkit_backend_pending_call, G_TYPE_OBJECT);

#define POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_BACKEND_TYPE_PENDING_CALL, PolkitBackendPendingCallPrivate))

static void
polkit_backend_pending_call_init (PolkitBackendPendingCall *pending_call)
{
  PolkitBackendPendingCallPrivate *priv;

  priv = POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE (pending_call);

}

static void
polkit_backend_pending_call_finalize (GObject *object)
{
  PolkitBackendPendingCall *pending_call;
  PolkitBackendPendingCallPrivate *priv;

  pending_call = POLKIT_BACKEND_PENDING_CALL (object);
  priv = POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE (pending_call);

  g_object_unref (priv->method_invocation);

  if (priv->inquirer != NULL)
    g_object_unref (priv->inquirer);

  G_OBJECT_CLASS (polkit_backend_pending_call_parent_class)->finalize (object);
}

static void
polkit_backend_pending_call_class_init (PolkitBackendPendingCallClass *klass)
{
  GObjectClass *gobject_class;

  gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_backend_pending_call_finalize;

  g_type_class_add_private (klass, sizeof (PolkitBackendPendingCallPrivate));
}

PolkitBackendPendingCall *
_polkit_backend_pending_call_new (EggDBusMethodInvocation *method_invocation)
{
  PolkitBackendPendingCall *pending_call;
  PolkitBackendPendingCallPrivate *priv;

  pending_call = POLKIT_BACKEND_PENDING_CALL (g_object_new (POLKIT_BACKEND_TYPE_PENDING_CALL,
                                                            NULL));

  priv = POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE (pending_call);

  priv->method_invocation = g_object_ref (method_invocation);

  return pending_call;
}

EggDBusMethodInvocation *
_polkit_backend_pending_call_get_method_invocation (PolkitBackendPendingCall *pending_call)
{
  PolkitBackendPendingCallPrivate *priv;
  priv = POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE (pending_call);
  return priv->method_invocation;
}


PolkitSubject *
polkit_backend_pending_call_get_caller (PolkitBackendPendingCall *pending_call)
{
  PolkitBackendPendingCallPrivate *priv;

  priv = POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE (pending_call);

  if (priv->inquirer != NULL)
    goto out;

  priv->inquirer = polkit_system_bus_name_new (egg_dbus_method_invocation_get_caller (priv->method_invocation));

 out:
  return priv->inquirer;
}

void
polkit_backend_pending_call_return_gerror (PolkitBackendPendingCall *pending_call,
                                           GError                   *error)
{
  PolkitBackendPendingCallPrivate *priv;

  priv = POLKIT_BACKEND_PENDING_CALL_GET_PRIVATE (pending_call);

  egg_dbus_method_invocation_return_gerror (priv->method_invocation,
                                            error);

  g_object_unref (pending_call);
}

void
polkit_backend_pending_call_return_error (PolkitBackendPendingCall *pending_call,
                                          GQuark                    domain,
                                          gint                      code,
                                          const gchar              *format,
                                          ...)
{
  GError *error;
  va_list va_args;
  gchar *literal_message;

  va_start (va_args, format);
  literal_message = g_strdup_vprintf (format, va_args);

  error = g_error_new_literal (domain,
                               code,
                               literal_message);

  polkit_backend_pending_call_return_gerror (pending_call, error);

  g_error_free (error);
  g_free (literal_message);
  va_end (va_args);
}


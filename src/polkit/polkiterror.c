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

#include "polkiterror.h"
#include "polkitprivate.h"

/**
 * SECTION:polkiterror
 * @title: PolkitError
 * @short_description: Error codes
 *
 * Error codes.
 */

static const GDBusErrorEntry polkit_error_entries[] =
{
  {POLKIT_ERROR_FAILED,         "org.freedesktop.PolicyKit1.Error.Failed"},
  {POLKIT_ERROR_CANCELLED,      "org.freedesktop.PolicyKit1.Error.Cancelled"},
  {POLKIT_ERROR_NOT_SUPPORTED,  "org.freedesktop.PolicyKit1.Error.NotSupported"},
  {POLKIT_ERROR_NOT_AUTHORIZED, "org.freedesktop.PolicyKit1.Error.NotAuthorized"},
};

GQuark
polkit_error_quark (void)
{
  static volatile gsize quark_volatile = 0;
  g_dbus_error_register_error_domain ("polkit-error-quark",
                                      &quark_volatile,
                                      polkit_error_entries,
                                      G_N_ELEMENTS (polkit_error_entries));
  G_STATIC_ASSERT (G_N_ELEMENTS (polkit_error_entries) - 1 == POLKIT_ERROR_NOT_AUTHORIZED);
  return (GQuark) quark_volatile;
}

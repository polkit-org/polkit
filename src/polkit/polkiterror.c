/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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
#include <polkit/polkiterror.h>

/**
 * SECTION:polkiterror
 * @title: PolkitError
 * @short_description: Error helper functions
 * @include: polkit/polkit.h
 *
 * Contains helper functions for reporting errors to the user.
 **/

/**
 * polkit_error_quark:
 *
 * Gets the #PolkitError Quark.
 *
 * Return value: a #GQuark.
 **/
GQuark
polkit_error_quark (void)
{
        return g_quark_from_static_string ("g-polkit-error-quark");
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
polkit_error_get_type (void)
{
        static GType etype = 0;

        if (etype == 0)
        {
                static const GEnumValue values[] = {
                        ENUM_ENTRY (POLKIT_ERROR_FAILED,        "Failed"),
                        ENUM_ENTRY (POLKIT_ERROR_NOT_SUPPORTED, "NotSupported"),
                        { 0, 0, 0 }
                };
                g_assert (POLKIT_ERROR_NUM_ERRORS == G_N_ELEMENTS (values) - 1);
                etype = g_enum_register_static ("PolkitErrorEnum", values);
        }
        return etype;
}

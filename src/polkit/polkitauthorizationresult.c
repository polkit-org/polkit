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
#include <polkit/polkitauthorizationresult.h>

/**
 * SECTION:polkitauthorizationresult
 * @title: PolkitAuthorizationResult
 * @short_description: Result of checking a claim
 * @include: polkit/polkit.h
 *
 * The #PolkitAuthorizationResult enumeration is for possible results
 * when checking whether a claim is authorized.
 **/

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
polkit_authorization_result_get_type (void)
{
        static GType etype = 0;

        if (etype == 0)
        {
                static const GEnumValue values[] = {
                        ENUM_ENTRY (POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED,   "NotAuthorized"),
                        ENUM_ENTRY (POLKIT_AUTHORIZATION_RESULT_AUTHORIZED,       "Authorized"),
                        ENUM_ENTRY (POLKIT_AUTHORIZATION_RESULT_CHALLENGE,        "Challenge"),
                        { 0, 0, 0 }
                };
                etype = g_enum_register_static ("PolkitAuthorizationResult", values);
        }
        return etype;
}

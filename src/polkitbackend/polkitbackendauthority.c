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
#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <polkit/polkit.h>
#include "polkitbackendauthority.h"

G_DEFINE_ABSTRACT_TYPE (PolkitBackendAuthority, polkit_backend_authority, G_TYPE_OBJECT);

static void
polkit_backend_authority_init (PolkitBackendAuthority *local_authority)
{
}

static void
polkit_backend_authority_class_init (PolkitBackendAuthorityClass *klass)
{
}

void
polkit_backend_authority_enumerate_actions (PolkitBackendAuthority   *authority,
                                            const gchar              *locale,
                                            PolkitBackendPendingCall *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_actions (authority, locale, pending_call);
}

void
polkit_backend_authority_enumerate_users (PolkitBackendAuthority   *authority,
                                          PolkitBackendPendingCall *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_users (authority, pending_call);
}

void
polkit_backend_authority_enumerate_groups (PolkitBackendAuthority   *authority,
                                           PolkitBackendPendingCall *pending_call)
{
  PolkitBackendAuthorityClass *klass;

  klass = POLKIT_BACKEND_AUTHORITY_GET_CLASS (authority);

  klass->enumerate_groups (authority, pending_call);
}

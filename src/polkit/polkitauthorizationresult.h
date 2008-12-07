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

#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_AUTHORIZATION_RESULT_H
#define __POLKIT_AUTHORIZATION_RESULT_H

#include <glib-object.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_AUTHORIZATION_RESULT (polkit_authorization_result_get_type ())

/**
 * PolkitAuthorizationResult:
 * @POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED: Not authorized.
 * @POLKIT_AUTHORIZATION_RESULT_AUTHORIZED: Authorized.
 * @POLKIT_AUTHORIZATION_RESULT_CHALLENGE: Can be authorized if further information is given.
 *
 * The possible results when checking whether a claim is authorized.
 */
typedef enum {
  POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED,
  POLKIT_AUTHORIZATION_RESULT_AUTHORIZED,
  POLKIT_AUTHORIZATION_RESULT_CHALLENGE
} PolkitAuthorizationResult;

GType polkit_authorization_result_get_type (void) G_GNUC_CONST;


G_END_DECLS

#endif /* __POLKIT_AUTHORIZATION_RESULT_H */


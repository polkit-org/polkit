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

#ifndef __POLKIT_AUTHORIZATION_RESULT_H
#define __POLKIT_AUTHORIZATION_RESULT_H

#include <glib-object.h>

G_BEGIN_DECLS

GType polkit_authorization_result_get_type (void) G_GNUC_CONST;

#define POLKIT_TYPE_AUTHORIZATION_RESULT (polkit_authorization_result_get_type ())

/**
 * PolkitAuthorizationResult:
 * @POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED: The subject is not authorized for the specified action
 * @POLKIT_AUTHORIZATION_RESULT_AUTHORIZED: The subject is authorized for the specified action
 * @POLKIT_AUTHORIZATION_RESULT_CHALLENGE: The subject is authorized if more information is provided
 *
 * Result codes for checking whether a subject is authorized for an action.
 */
typedef enum
{
  POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED = 0,
  POLKIT_AUTHORIZATION_RESULT_AUTHORIZED = 1,
  POLKIT_AUTHORIZATION_RESULT_CHALLENGE = 2,
} PolkitAuthorizationResult;

G_END_DECLS

#endif /* __POLKIT_AUTHORIZATION_RESULT_H */

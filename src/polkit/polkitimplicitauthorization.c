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
#include "polkitprivate.h"

gboolean
polkit_implicit_authorization_from_string (const gchar *string,
                                           PolkitImplicitAuthorization *out_implicit_authorization)
{
  PolkitImplicitAuthorization result;
  gboolean ret;

  ret = TRUE;
  result = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;

  if (strcmp (string, "no") == 0)
    {
      result = POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED;
    }
  else if (strcmp (string, "auth_self") == 0)
    {
      result = POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED;
    }
  else if (strcmp (string, "auth_admin") == 0)
    {
      result = POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED;
    }
  else if (strcmp (string, "auth_self_keep") == 0)
    {
      result = POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED;
    }
  else if (strcmp (string, "auth_admin_keep") == 0)
    {
      result = POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED;
    }
  else if (strcmp (string, "yes") == 0)
    {
      result = POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED;
    }
  else
    {
      g_warning ("Unknown PolkitImplicitAuthorization string '%s'", string);
      ret = FALSE;
      result = POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN;
    }

  if (out_implicit_authorization != NULL)
    *out_implicit_authorization = result;

  return ret;
}

const gchar *
polkit_implicit_authorization_to_string (PolkitImplicitAuthorization implicit_authorization)
{
  const gchar *s;

  s = "(unknown)";

  switch (implicit_authorization)
    {
    case POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN:
      s = "unknown";
      break;

    case POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED:
      s = "no";
      break;

    case POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED:
      s = "auth_self";
      break;

    case POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED:
      s = "auth_admin";
      break;

    case POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED:
      s = "auth_self_keep";
      break;

    case POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED:
      s = "auth_admin_keep";
      break;

    case POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED:
      s = "yes";
      break;
    }

  return s;
}

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-privilege.c : privilege
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "libpolkit-privilege.h"

struct PolKitPrivilege_s
{
};

PolKitPrivilege *
libpolkit_privilege_new (void)
{
        return NULL;
}

PolKitPrivilege *
libpolkit_privilege_ref (PolKitPrivilege *privilege)
{
        return privilege;
}

void
libpolkit_privilege_set_privilege_id (PolKitPrivilege *privilege, const char  *privilege_id)
{
}

gboolean
libpolkit_privilege_get_privilege_id (PolKitPrivilege *privilege, char **out_privilege_id)
{
        return FALSE;
}

void
libpolkit_privilege_unref (PolKitPrivilege *privilege)
{
}

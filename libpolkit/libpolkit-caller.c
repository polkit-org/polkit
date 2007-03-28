/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-caller.c : callers
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
#include "libpolkit-caller.h"

struct PolKitCaller_s
{
};

PolKitCaller *
libpolkit_caller_new (void)
{
        return NULL;
}

PolKitCaller *
libpolkit_caller_ref (PolKitCaller *caller)
{
        return caller;
}

void
libpolkit_caller_set_dbus_name (PolKitCaller *caller, const char *dbus_name)
{
}

void
libpolkit_caller_set_uid (PolKitCaller *caller, uid_t uid)
{
}

void
libpolkit_caller_set_pid (PolKitCaller *caller, pid_t pid)
{
}

void
libpolkit_caller_set_selinux_context (PolKitCaller *caller, const char *selinux_context)
{
}

void
libpolkit_caller_set_ck_session (PolKitCaller *caller, PolKitSession *session)
{
}

gboolean
libpolkit_caller_get_dbus_name (PolKitCaller *caller, char **out_dbus_name)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_uid (PolKitCaller *caller, uid_t *out_uid)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_pid (PolKitCaller *caller, uid_t *out_pid)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_selinux_context (PolKitCaller *caller, char *out_selinux_context)
{
        return FALSE;
}

gboolean
libpolkit_caller_get_ck_session (PolKitCaller *caller, PolKitSession **out_session)
{
        return FALSE;
}

void
libpolkit_caller_unref (PolKitCaller *caller)
{
}

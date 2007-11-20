/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-simple.h : Simple convenience interface
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_DBUS_H)
#error "Only <polkit-dbus/polkit-dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_SIMPLE_H
#define POLKIT_SIMPLE_H

#include <polkit-dbus/polkit-dbus.h>

POLKIT_BEGIN_DECLS

polkit_uint64_t polkit_check_auth (pid_t pid, ...);
polkit_uint64_t polkit_check_authv (pid_t pid, const char **action_ids);

polkit_bool_t   polkit_auth_obtain (const char *action_id, polkit_uint32_t xid, pid_t pid, DBusError *error);

POLKIT_END_DECLS

#endif /* POLKIT_SIMPLE_H */

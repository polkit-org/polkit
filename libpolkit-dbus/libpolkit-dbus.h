/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-dbus.h : helper library for obtaining seat, session and
 * caller information via D-Bus and ConsoleKit
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

#ifndef LIBPOLKIT_DBUS_H
#define LIBPOLKIT_DBUS_H

#include <libpolkit/libpolkit.h>
#include <dbus/dbus.h>

PolKitSession *libpolkit_session_new_from_objpath   (DBusConnection *con, const char *objpath, uid_t uid, DBusError *error);
PolKitSession *libpolkit_session_new_from_cookie    (DBusConnection *con, const char *cookie, DBusError *error);

PolKitCaller     *libpolkit_caller_new_from_dbus_name  (DBusConnection *con, const char *dbus_name, DBusError *error);


#endif /* LIBPOLKIT_DBUS_H */



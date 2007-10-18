/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-dbus.h : helper library for obtaining seat, session and
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

#ifndef POLKIT_DBUS_H
#define POLKIT_DBUS_H

#include <polkit/polkit.h>
#include <dbus/dbus.h>

PolKitSession *polkit_session_new_from_objpath   (DBusConnection *con, const char *objpath, uid_t uid, DBusError *error);
PolKitSession *polkit_session_new_from_cookie    (DBusConnection *con, const char *cookie, DBusError *error);

PolKitCaller  *polkit_caller_new_from_dbus_name  (DBusConnection *con, const char *dbus_name, DBusError *error);

PolKitCaller  *polkit_caller_new_from_pid  (DBusConnection *con, pid_t pid, DBusError *error);



struct _PolKitTracker;
typedef struct _PolKitTracker PolKitTracker;

PolKitTracker *polkit_tracker_new                        (void);
PolKitTracker *polkit_tracker_ref                        (PolKitTracker *pk_tracker);
void           polkit_tracker_unref                      (PolKitTracker *pk_tracker);
void           polkit_tracker_set_system_bus_connection  (PolKitTracker *pk_tracker, DBusConnection *con);
void           polkit_tracker_init                       (PolKitTracker *pk_tracker);

polkit_bool_t  polkit_tracker_dbus_func                  (PolKitTracker *pk_tracker, DBusMessage *message);

PolKitCaller  *polkit_tracker_get_caller_from_dbus_name  (PolKitTracker *pk_tracker, const char *dbus_name, DBusError *error);

PolKitCaller  *polkit_tracker_get_caller_from_pid        (PolKitTracker *pk_tracker, pid_t pid, DBusError *error);


#endif /* POLKIT_DBUS_H */



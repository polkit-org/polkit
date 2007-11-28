/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-dbus.h : helper library for obtaining seat, session and
 * caller information via D-Bus and ConsoleKit
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/

#ifndef POLKIT_DBUS_H
#define POLKIT_DBUS_H

#include <polkit/polkit.h>
#include <dbus/dbus.h>

#define _POLKIT_INSIDE_POLKIT_DBUS_H 1
#include <polkit-dbus/polkit-simple.h>
#undef _POLKIT_INSIDE_POLKIT_DBUS_H

POLKIT_BEGIN_DECLS

PolKitSession *polkit_session_new_from_objpath   (DBusConnection *con, const char *objpath, uid_t uid, DBusError *error);
PolKitSession *polkit_session_new_from_cookie    (DBusConnection *con, const char *cookie, DBusError *error);

PolKitCaller  *polkit_caller_new_from_dbus_name  (DBusConnection *con, const char *dbus_name, DBusError *error);

PolKitCaller  *polkit_caller_new_from_pid  (DBusConnection *con, pid_t pid, DBusError *error);

polkit_bool_t  polkit_is_authorization_relevant (DBusConnection *con, PolKitAuthorization *auth, DBusError *error);


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

polkit_bool_t  polkit_tracker_is_authorization_relevant  (PolKitTracker *pk_tracker, PolKitAuthorization *auth, DBusError *error);

POLKIT_END_DECLS

#endif /* POLKIT_DBUS_H */

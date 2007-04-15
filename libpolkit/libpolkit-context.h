/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-context.h : PolicyKit context
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <libpolkit/libpolkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef LIBPOLKIT_CONTEXT_H
#define LIBPOLKIT_CONTEXT_H

#include <libpolkit/libpolkit-types.h>
#include <libpolkit/libpolkit-error.h>
#include <libpolkit/libpolkit-result.h>
#include <libpolkit/libpolkit-context.h>
#include <libpolkit/libpolkit-action.h>
#include <libpolkit/libpolkit-resource.h>
#include <libpolkit/libpolkit-seat.h>
#include <libpolkit/libpolkit-session.h>
#include <libpolkit/libpolkit-caller.h>
#include <libpolkit/libpolkit-policy-cache.h>

struct PolKitContext;
typedef struct PolKitContext PolKitContext;

/**
 * PolKitContextConfigChangedCB:
 * @pk_context: PolicyKit context
 * @user_data: user data
 *
 * The type of the callback function for when configuration changes.
 * Mechanisms should use this callback to e.g. reconfigure all
 * permissions / acl's they have set in response to policy decisions
 * made from information provided by PolicyKit.
 *
 * Note that this function may be called many times within a short
 * interval due to how file monitoring works if e.g. the user is
 * editing a configuration file (editors typically create back-up
 * files). Mechanisms should use a "cool-off" timer (of, say, one
 * second) to avoid doing many expensive operations (such as
 * reconfiguring all ACL's for all devices) within a very short
 * timeframe.
 */
typedef void (*PolKitContextConfigChangedCB) (PolKitContext  *pk_context,
                                              void           *user_data);

/**
 * PolKitContextFileMonitorEvent:
 * @POLKIT_CONTEXT_FILE_MONITOR_EVENT_NONE: TODO
 * @POLKIT_CONTEXT_FILE_MONITOR_EVENT_ACCESS: watch when a file is accessed
 * @POLKIT_CONTEXT_FILE_MONITOR_EVENT_CREATE: watch when a file is created
 * @POLKIT_CONTEXT_FILE_MONITOR_EVENT_DELETE: watch when a file is deleted
 * @POLKIT_CONTEXT_FILE_MONITOR_EVENT_CHANGE: watch when a file changes
 *
 * File monitoring events.
 **/
typedef enum
{
        POLKIT_CONTEXT_FILE_MONITOR_EVENT_NONE    = 1 << 0,
        POLKIT_CONTEXT_FILE_MONITOR_EVENT_ACCESS  = 1 << 1,
        POLKIT_CONTEXT_FILE_MONITOR_EVENT_CREATE  = 1 << 2,
        POLKIT_CONTEXT_FILE_MONITOR_EVENT_DELETE  = 1 << 3,
        POLKIT_CONTEXT_FILE_MONITOR_EVENT_CHANGE  = 1 << 4,
} PolKitContextFileMonitorEvent;

/**
 * PolKitContextFileMonitorNotifyFunc:
 * @pk_context: PolicyKit context
 * @event_mask: event that happened
 * @path: the path to the monitored file
 * @user_data: the user data supplied to the function of type #PolKitContextFileMonitorAddWatch
 *
 * Callback when an event happens on a file that is monitored.
 **/
typedef void (*PolKitContextFileMonitorNotifyFunc) (PolKitContext                 *pk_context,
                                                    PolKitContextFileMonitorEvent  event_mask,
                                                    const char                    *path,
                                                    void                          *user_data);

/**
 * PolKitContextFileMonitorAddWatch:
 * @pk_context: PolicyKit context
 * @path: path to file/directory to monitor for events
 * @event_mask: events to look for
 * @notify_cb: function to call on events
 * @user_data: user data
 *
 * The type of a function that PolicyKit can use to watch file
 * events. This function must call the supplied @notify_cb function
 * (and pass @path and @user_data) on events
 *
 * Returns: A handle for the watch. If zero it means the file cannot
 * be watched. Caller can remove the watch using the supplied function
 * of type #PolKitContextFileMonitorRemoveWatch and the handle.
 */
typedef int (*PolKitContextFileMonitorAddWatch) (PolKitContext                     *pk_context,
                                                 const char                        *path,
                                                 PolKitContextFileMonitorEvent      event_mask,
                                                 PolKitContextFileMonitorNotifyFunc notify_cb,
                                                 void                              *user_data);

/**
 * PolKitContextFileMonitorRemoveWatch:
 * @pk_context: PolicyKit context
 * @watch_id: the watch id
 *
 * The type of a function that PolicyKit can use to stop monitoring
 * file events. Pass the handle obtained from the supplied function of
 * type #PolKitContextFileMonitorAddWatch.
 */
typedef void (*PolKitContextFileMonitorRemoveWatch) (PolKitContext                     *pk_context,
                                                     int                                watch_id);


PolKitContext *libpolkit_context_new                (void);
void           libpolkit_context_set_config_changed (PolKitContext                        *pk_context, 
                                                     PolKitContextConfigChangedCB          cb, 
                                                     void                                 *user_data);
void           libpolkit_context_set_file_monitor   (PolKitContext                        *pk_context, 
                                                     PolKitContextFileMonitorAddWatch      add_watch_func,
                                                     PolKitContextFileMonitorRemoveWatch   remove_watch_func);
polkit_bool_t  libpolkit_context_init               (PolKitContext                        *pk_context, 
                                                     PolKitError                         **error);
PolKitContext *libpolkit_context_ref                (PolKitContext                        *pk_context);
void           libpolkit_context_unref              (PolKitContext                        *pk_context);

PolKitPolicyCache *libpolkit_context_get_policy_cache (PolKitContext *pk_context);

/**
 * PolKitSeatVisitorCB:
 * @seat: the seat
 * @resources_associated_with_seat: A NULL terminated array of resources associated with the seat
 * @user_data: user data
 *
 * Visitor function for libpolkit_get_seat_resource_association(). The caller should _not_ unref the passed objects.
 */
typedef void (*PolKitSeatVisitorCB) (PolKitSeat      *seat,
                                     PolKitResource **resources_associated_with_seat,
                                     void            *user_data);

PolKitResult
libpolkit_context_get_seat_resource_association (PolKitContext       *pk_context,
                                                 PolKitSeatVisitorCB  visitor,
                                                 void                *user_data);

PolKitResult
libpolkit_context_is_resource_associated_with_seat (PolKitContext   *pk_context,
                                                    PolKitResource  *resource,
                                                    PolKitSeat      *seat);

PolKitResult
libpolkit_context_can_session_access_resource (PolKitContext   *pk_context,
                                               PolKitAction *action,
                                               PolKitResource  *resource,
                                               PolKitSession   *session);

PolKitResult
libpolkit_context_can_caller_access_resource (PolKitContext   *pk_context,
                                              PolKitAction *action,
                                              PolKitResource  *resource,
                                              PolKitCaller    *caller);

#endif /* LIBPOLKIT_CONTEXT_H */



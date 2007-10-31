/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-context.h : PolicyKit context
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
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_CONTEXT_H
#define POLKIT_CONTEXT_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-error.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-context.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-seat.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-policy-cache.h>
#include <polkit/polkit-config.h>
#include <polkit/polkit-authorization-db.h>

POLKIT_BEGIN_DECLS

struct _PolKitContext;
typedef struct _PolKitContext PolKitContext;

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
 * The user must have set up watches using #polkit_context_set_io_watch_functions
 * for this to work.
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
 * PolKitContextAddIOWatch:
 * @pk_context: the polkit context
 * @fd: the file descriptor to watch
 *
 * Type for function supplied by the application to integrate a watch
 * on a file descriptor into the applications main loop. The
 * application must call polkit_grant_io_func() when there is data
 * to read from the file descriptor.
 *
 * For glib mainloop, the function will typically look like this:
 *
 * <programlisting>
 * static gboolean
 * io_watch_have_data (GIOChannel *channel, GIOCondition condition, gpointer user_data)
 * {
 *         int fd;
 *         PolKitContext *pk_context = user_data;
 *         fd = g_io_channel_unix_get_fd (channel);
 *         polkit_context_io_func (pk_context, fd);
 *         return TRUE;
 * }
 * 
 * static int 
 * io_add_watch (PolKitContext *pk_context, int fd)
 * {
 *         guint id = 0;
 *         GIOChannel *channel;
 *         channel = g_io_channel_unix_new (fd);
 *         if (channel == NULL)
 *                 goto out;
 *         id = g_io_add_watch (channel, G_IO_IN, io_watch_have_data, pk_context);
 *         if (id == 0) {
 *                 g_io_channel_unref (channel);
 *                 goto out;
 *         }
 *         g_io_channel_unref (channel);
 * out:
 *         return id;
 * }
 * </programlisting>
 *
 * Returns: 0 if the watch couldn't be set up; otherwise an unique
 * identifier for the watch.
 **/
typedef int (*PolKitContextAddIOWatch) (PolKitContext *pk_context, int fd);

/**
 * PolKitContextRemoveIOWatch:
 * @pk_context: the context object
 * @watch_id: the id obtained from using the supplied function
 * of type #PolKitContextAddIOWatch
 *
 * Type for function supplied by the application to remove a watch set
 * up via the supplied function of type #PolKitContextAddIOWatch
 *
 * For the glib mainloop, the function will typically look like this:
 *
 * <programlisting>
 * static void 
 * io_remove_watch (PolKitContext *pk_context, int watch_id)
 * {
 *         g_source_remove (watch_id);
 * }
 * </programlisting>
 *
 **/
typedef void (*PolKitContextRemoveIOWatch) (PolKitContext *pk_context, int watch_id);


PolKitContext *polkit_context_new                    (void);
void           polkit_context_set_config_changed     (PolKitContext                        *pk_context, 
                                                      PolKitContextConfigChangedCB          cb, 
                                                      void                                 *user_data);
void           polkit_context_set_io_watch_functions (PolKitContext                        *pk_context,
                                                      PolKitContextAddIOWatch               io_add_watch_func,
                                                      PolKitContextRemoveIOWatch            io_remove_watch_func);
void           polkit_context_set_load_descriptions  (PolKitContext                        *pk_context);
polkit_bool_t  polkit_context_init                   (PolKitContext                        *pk_context, 
                                                      PolKitError                         **error);
PolKitContext *polkit_context_ref                    (PolKitContext                        *pk_context);
void           polkit_context_unref                  (PolKitContext                        *pk_context);

void           polkit_context_io_func                (PolKitContext *pk_context, int fd);

PolKitPolicyCache *polkit_context_get_policy_cache   (PolKitContext *pk_context);

POLKIT_GNUC_DEPRECATED
PolKitResult polkit_context_can_session_do_action    (PolKitContext   *pk_context,
                                                      PolKitAction    *action,
                                                      PolKitSession   *session);

POLKIT_GNUC_DEPRECATED 
PolKitResult polkit_context_can_caller_do_action     (PolKitContext   *pk_context,
                                                      PolKitAction    *action,
                                                      PolKitCaller    *caller);

PolKitConfig *polkit_context_get_config (PolKitContext *pk_context, PolKitError **error);

PolKitResult polkit_context_is_caller_authorized (PolKitContext         *pk_context,
                                                  PolKitAction          *action,
                                                  PolKitCaller          *caller,
                                                  polkit_bool_t          is_mechanism);

PolKitResult polkit_context_is_session_authorized (PolKitContext         *pk_context,
                                                   PolKitAction          *action,
                                                   PolKitSession         *session,
                                                   polkit_bool_t          is_mechanism);

PolKitAuthorizationDB *polkit_context_get_authorization_db (PolKitContext *pk_context);

POLKIT_END_DECLS

#endif /* POLKIT_CONTEXT_H */



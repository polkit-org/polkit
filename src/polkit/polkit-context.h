/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-context.h : PolicyKit context
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
#include <polkit/polkit-action-description.h>
#include <polkit/polkit-seat.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>
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
 * PolKitActionDescriptionForeachFunc:
 * @action_description: the entry
 * @user_data: user data
 *
 * Type for function used in to iterate over action descriptions.
 *
 * Returns: #TRUE to short-circuit, e.g.  stop the iteration
 **/
typedef polkit_bool_t (*PolKitActionDescriptionForeachFunc) (PolKitActionDescription *action_description,
                                                             void                    *user_data);

PolKitContext *polkit_context_new                    (void);
void           polkit_context_set_config_changed     (PolKitContext                        *pk_context, 
                                                      PolKitContextConfigChangedCB          cb, 
                                                      void                                 *user_data);
polkit_bool_t  polkit_context_init                   (PolKitContext                        *pk_context, 
                                                      PolKitError                         **error);
PolKitContext *polkit_context_ref                    (PolKitContext                        *pk_context);
void           polkit_context_unref                  (PolKitContext                        *pk_context);

PolKitResult polkit_context_is_caller_authorized (PolKitContext         *pk_context,
                                                  PolKitAction          *action,
                                                  PolKitCaller          *caller,
                                                  polkit_bool_t          revoke_if_one_shot,
                                                  PolKitError          **error);

PolKitResult polkit_context_is_session_authorized (PolKitContext         *pk_context,
                                                   PolKitAction          *action,
                                                   PolKitSession         *session,
                                                   PolKitError          **error);

polkit_bool_t polkit_context_action_description_foreach (PolKitContext                      *pk_context,
                                                         PolKitActionDescriptionForeachFunc  cb,
                                                         void                               *user_data);

PolKitActionDescription *polkit_context_get_action_description (PolKitContext   *pk_context,
                                                                const char      *action_id);

/* TODO: move to private static lib */
polkit_bool_t polkit_action_description_get_from_file (const char                         *path,
                                                       PolKitActionDescriptionForeachFunc  cb,
                                                       void                               *user_data,
                                                       PolKitError                       **error);


PolKitAuthorizationDB *polkit_context_get_authorization_db (PolKitContext *pk_context);

POLKIT_END_DECLS

#endif /* POLKIT_CONTEXT_H */



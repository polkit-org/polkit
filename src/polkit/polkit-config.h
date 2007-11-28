/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-config.h : Configuration file
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

#ifndef POLKIT_CONFIG_H
#define POLKIT_CONFIG_H

#include <sys/types.h>
#include <polkit/polkit-types.h>
#include <polkit/polkit-error.h>
#include <polkit/polkit-types.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>

POLKIT_BEGIN_DECLS

struct _PolKitConfig;
typedef struct _PolKitConfig PolKitConfig;

PolKitConfig  *polkit_config_new                    (const char *path, PolKitError **error);
PolKitConfig  *polkit_config_ref                    (PolKitConfig *pk_config);
void           polkit_config_unref                  (PolKitConfig *pk_config);

PolKitResult
polkit_config_can_session_do_action                 (PolKitConfig   *pk_config,
                                                     PolKitAction    *action,
                                                     PolKitSession   *session);

PolKitResult
polkit_config_can_caller_do_action                  (PolKitConfig   *pk_config,
                                                     PolKitAction    *action,
                                                     PolKitCaller    *caller);

/**
 * PolKitConfigAdminAuthType:
 * @POLKIT_CONFIG_ADMIN_AUTH_TYPE_USER: Authentication as
 * administrator matches one or more users
 * @POLKIT_CONFIG_ADMIN_AUTH_TYPE_GROUP: Authentication as
 * administrator matches users from one or more groups
 *
 * This enumeration reflects results defined in the
 * "define_admin_auth" configuration element.
 */
typedef enum
{
        POLKIT_CONFIG_ADMIN_AUTH_TYPE_USER,
        POLKIT_CONFIG_ADMIN_AUTH_TYPE_GROUP
} PolKitConfigAdminAuthType;

polkit_bool_t polkit_config_determine_admin_auth_type (PolKitConfig                *pk_config,
                                                       PolKitAction                *action,
                                                       PolKitCaller                *caller,
                                                       PolKitConfigAdminAuthType   *out_admin_auth_type,
                                                       const char                 **out_data);

POLKIT_END_DECLS

#endif /* POLKIT_CONFIG_H */



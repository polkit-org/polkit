/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-default.h : policy definition for the defaults
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

#ifndef LIBPOLKIT_POLICY_DEFAULT_H
#define LIBPOLKIT_POLICY_DEFAULT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

#include <libpolkit/libpolkit-result.h>
#include <libpolkit/libpolkit-action.h>
#include <libpolkit/libpolkit-resource.h>
#include <libpolkit/libpolkit-session.h>
#include <libpolkit/libpolkit-caller.h>

struct PolKitPolicyDefault;
typedef struct PolKitPolicyDefault PolKitPolicyDefault;

PolKitPolicyDefault *libpolkit_policy_default_new   (GKeyFile *key_file, const char *action, GError **error);
PolKitPolicyDefault *libpolkit_policy_default_ref   (PolKitPolicyDefault *policy_default);
void                    libpolkit_policy_default_unref (PolKitPolicyDefault *policy_default);
void                    libpolkit_policy_default_debug (PolKitPolicyDefault *policy_default);

PolKitResult libpolkit_policy_default_can_session_access_resource (PolKitPolicyDefault *policy_default,
                                                                      PolKitAction        *action,
                                                                      PolKitResource         *resource,
                                                                      PolKitSession          *session);
PolKitResult libpolkit_policy_default_can_caller_access_resource (PolKitPolicyDefault *policy_default,
                                                                     PolKitAction        *action,
                                                                     PolKitResource         *resource,
                                                                     PolKitCaller           *caller);

/* TODO: export knobs for "default policy" */

#endif /* LIBPOLKIT_POLICY_DEFAULT_H */



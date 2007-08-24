/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-cache.h : policy cache
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

#ifndef POLKIT_POLICY_CACHE_H
#define POLKIT_POLICY_CACHE_H

#include <polkit/polkit-error.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-policy-file-entry.h>

struct _PolKitPolicyCache;
typedef struct _PolKitPolicyCache PolKitPolicyCache;

/**
 * PolKitPolicyCacheForeachFunc:
 * @policy_cache: the policy cache
 * @entry: an entry in the cache - do not unref
 * @user_data: user data passed to polkit_policy_cache_foreach()
 *
 * Callback function for polkit_policy_cache_foreach().
 **/
typedef void (*PolKitPolicyCacheForeachFunc) (PolKitPolicyCache *policy_cache,
                                              PolKitPolicyFileEntry *entry,
                                              void *user_data);

PolKitPolicyCache     *polkit_policy_cache_ref       (PolKitPolicyCache *policy_cache);
void                   polkit_policy_cache_unref     (PolKitPolicyCache *policy_cache);
void                   polkit_policy_cache_debug     (PolKitPolicyCache *policy_cache);
PolKitPolicyFileEntry* polkit_policy_cache_get_entry (PolKitPolicyCache *policy_cache, 
                                                      PolKitAction *action);
PolKitPolicyFileEntry* polkit_policy_cache_get_entry_by_id (PolKitPolicyCache *policy_cache, 
                                                            const char *action_id);
void                   polkit_policy_cache_foreach   (PolKitPolicyCache *policy_cache, 
                                                      PolKitPolicyCacheForeachFunc callback,
                                                      void *user_data);

#endif /* POLKIT_POLICY_CACHE_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-policy-cache.h : policy cache
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

#ifndef LIBPOLKIT_POLICY_CACHE_H
#define LIBPOLKIT_POLICY_CACHE_H

#include <libpolkit/libpolkit-error.h>
#include <libpolkit/libpolkit-action.h>
#include <libpolkit/libpolkit-policy-file-entry.h>

struct PolKitPolicyCache;
typedef struct PolKitPolicyCache PolKitPolicyCache;

PolKitPolicyCache *libpolkit_policy_cache_new                   (const char *dirname, PolKitError **error);
PolKitPolicyCache *libpolkit_policy_cache_ref                   (PolKitPolicyCache *policy_cache);
void               libpolkit_policy_cache_unref                 (PolKitPolicyCache *policy_cache);
void               libpolkit_policy_cache_debug                 (PolKitPolicyCache *policy_cache);

PolKitPolicyFileEntry* libpolkit_policy_cache_get_entry (PolKitPolicyCache *policy_cache,
                                                         PolKitAction      *action);

#endif /* LIBPOLKIT_POLICY_CACHE_H */



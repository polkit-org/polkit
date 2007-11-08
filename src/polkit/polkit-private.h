/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-private.h : Private functions
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

#if !defined (POLKIT_COMPILATION)
#error "This is a private file and shouldn't be included outside PolicyKit."
#endif

#ifndef POLKIT_PRIVATE_H
#define POLKIT_PRIVATE_H

#include <glib.h>
#include <polkit/polkit.h>
#include <polkit/polkit-memory.h>
#include <polkit/polkit-hash.h>

/**
 * SECTION:polkit-private
 * @short_description: Private symbols for libpolkit
 *
 * Private symbols for libpolkit.
 */

POLKIT_BEGIN_DECLS

void  _polkit_memory_reset (void);
int   _polkit_memory_get_current_allocations (void);
int   _polkit_memory_get_total_allocations (void);
void  _polkit_memory_fail_nth_alloc (int number);

PolKitAuthorization *_polkit_authorization_new_for_uid (const char *entry_in_auth_file, uid_t uid);
const char *_polkit_authorization_get_authfile_entry (PolKitAuthorization *auth);

PolKitAuthorizationConstraint *_polkit_authorization_constraint_new (const char *entry_in_auth_file);

polkit_bool_t _polkit_authorization_db_auth_file_add (const char *root, polkit_bool_t transient, uid_t uid, char *str_to_add);

PolKitAuthorizationDB *_polkit_authorization_db_new            (void);
void                   _polkit_authorization_db_invalidate_cache (PolKitAuthorizationDB *authdb);

void                   _polkit_authorization_db_pfe_foreach   (PolKitPolicyCache *policy_cache, 
                                                               PolKitPolicyCacheForeachFunc callback,
                                                               void *user_data);

PolKitPolicyFileEntry* _polkit_authorization_db_pfe_get_by_id (PolKitPolicyCache *policy_cache, 
                                                               const char *action_id);


PolKitPolicyCache     *_polkit_policy_cache_new       (const char *dirname, polkit_bool_t load_descriptions, PolKitError **error);

PolKitPolicyCache *_polkit_policy_cache_new       (const char *dirname, polkit_bool_t load_descriptions, PolKitError **error);

PolKitPolicyDefault *_polkit_policy_default_new (PolKitResult defaults_allow_any,
                                                 PolKitResult defaults_allow_inactive,
                                                 PolKitResult defaults_allow_active);

polkit_bool_t _polkit_policy_file_entry_set_descriptions (PolKitPolicyFileEntry *pfe,
                                                          const char *policy_description,
                                                          const char *policy_message);


PolKitPolicyDefault *_polkit_policy_default_new (PolKitResult defaults_allow_any,
                                                 PolKitResult defaults_allow_inactive,
                                                 PolKitResult defaults_allow_active);


PolKitPolicyFileEntry *_polkit_policy_file_entry_new   (const char *action_id, 
                                                        PolKitResult defaults_allow_any,
                                                        PolKitResult defaults_allow_inactive,
                                                        PolKitResult defaults_allow_active,
                                                        PolKitHash *annotations);


#ifdef POLKIT_AUTHDB_DUMMY
struct _PolKitAuthorizationDB
{
        /*< private >*/
        int refcount;
};
#elif POLKIT_AUTHDB_DEFAULT
struct _PolKitAuthorizationDB
{
        /*< private >*/
        int refcount;
        GHashTable *uid_to_authlist;
};

#endif

POLKIT_END_DECLS

#endif /* POLKIT_PRIVATE_H */


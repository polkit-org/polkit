/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-private.h : Private functions
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

#if !defined (POLKIT_COMPILATION)
#error "This is a private file and shouldn't be included outside PolicyKit."
#endif

#ifndef POLKIT_PRIVATE_H
#define POLKIT_PRIVATE_H

#include <kit/kit.h>
#include <polkit/polkit.h>
#include <polkit/polkit-debug.h>

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

polkit_bool_t _polkit_authorization_db_auth_file_add (polkit_bool_t transient, uid_t uid, char *str_to_add);

PolKitAuthorizationDB *_polkit_authorization_db_new            (void);
void                   _polkit_authorization_db_invalidate_cache (PolKitAuthorizationDB *authdb);

polkit_bool_t          _polkit_authorization_db_pfe_foreach   (PolKitPolicyCache *policy_cache, 
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
                                                        const char *vendor,
                                                        const char *vendor_url,
                                                        const char *icon_name,
                                                        PolKitResult defaults_allow_any,
                                                        PolKitResult defaults_allow_inactive,
                                                        PolKitResult defaults_allow_active,
                                                        KitHash *annotations);


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
        KitHash *uid_to_authlist;
};

#endif

POLKIT_END_DECLS

#endif /* POLKIT_PRIVATE_H */


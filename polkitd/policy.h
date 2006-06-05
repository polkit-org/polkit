/***************************************************************************
 * CVSID: $Id$
 *
 * policy.h : Wraps policy
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
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

#ifndef POLICY_H
#define POLICY_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

typedef enum {
	POLICY_RESULT_OK,
	POLICY_RESULT_ERROR,
	POLICY_RESULT_NO_SUCH_POLICY
} PolicyResult;

typedef gboolean (*HaveTempPrivCB) (uid_t        user,
				    const char  *privilege,
				    const char  *resource,
				    gboolean     ignore_resource,
				    gpointer     userdata);


PolicyResult policy_get_policies                                  (GList         **result);

PolicyResult policy_is_uid_allowed_for_policy                     (uid_t           uid, 
								   const char     *policy, 
								   const char     *resource,
								   gboolean       *out_is_privileged,
								   gboolean       *out_is_temporary,
								   char          **out_is_privileged_but_restricted,
								   gpointer        have_temp_privilege_userdata,
								   HaveTempPrivCB  have_temp_privilege);
								   

PolicyResult policy_get_auth_details_for_policy                   (uid_t           uid,
								   const char     *policy,
								   const char     *resource,
								   gboolean       *out_auth_can_obtain,
								   gboolean       *out_auth_can_obtain_is_temporary,
								   gboolean       *out_auth_can_grant,
								   gboolean       *out_auth_obtain_requires_root,
								   gpointer        have_temp_privilege_userdata,
								   HaveTempPrivCB  have_temp_privilege);


PolicyResult policy_get_allowed_resources_for_policy_for_uid      (uid_t           uid, 
								   const char     *policy, 
								   GList         **result);

PolicyResult policy_get_allowed_resources_for_policy_for_uid_gid  (uid_t           uid, 
								   guint           num_gids,
								   gid_t          *gid_list,
								   const char     *policy, 
								   GList         **result);

PolicyResult policy_is_uid_gid_allowed_for_policy                 (uid_t           uid, 
								   guint           num_gids,
								   gid_t          *gid_list,
								   const char     *policy, 
								   const char     *resource,
								   gboolean       *out_is_privileged,
								   gboolean       *out_is_temporary,
								   char          **out_is_privileged_but_restricted,
								   gpointer        have_temp_privilege_userdata,
								   HaveTempPrivCB  have_temp_privilege);

char        *policy_util_uid_to_name                              (uid_t           uid, 
								   gid_t          *default_gid);

char        *policy_util_gid_to_name                              (gid_t           gid);

uid_t        policy_util_name_to_uid                              (const char     *username, 
								   gid_t          *default_gid);

gid_t        policy_util_name_to_gid                              (const char     *groupname);

void         policy_util_set_policy_directory                     (const char     *directory);

#endif /* POLICY_H */



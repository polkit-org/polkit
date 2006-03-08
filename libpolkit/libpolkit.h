/***************************************************************************
 *
 * libpolkit.h : Simple library for system software to query policy and 
 *               UI shells to query and modify policy
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
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

#ifndef LIBPOLKIT_H
#define LIBPOLKIT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

typedef enum {
	LIBPOLKIT_RESULT_OK,
	LIBPOLKIT_RESULT_ERROR,
	LIBPOLKIT_RESULT_INVALID_CONTEXT,
	LIBPOLKIT_RESULT_PERMISSON_DENIED,
	LIBPOLKIT_RESULT_NO_SUCH_POLICY
} LibPolKitResult;

struct LibPolKitContext_s;
typedef struct LibPolKitContext_s LibPolKitContext;


typedef enum {
	LIBPOLKIT_ELEMENT_TYPE_UID,
	LIBPOLKIT_ELEMENT_TYPE_GID
} LibPolKitElementType;

struct LibPolKitElement_s;
typedef struct LibPolKitElement_s LibPolKitElement;


LibPolKitContext  *libpolkit_new_context                    (void);

gboolean           libpolkit_context_set_txt_source         (LibPolKitContext     *ctx,
							     const char            *directory);

gboolean           libpolkit_free_context                   (LibPolKitContext     *ctx);

LibPolKitResult    libpolkit_get_policies                   (LibPolKitContext     *ctx,
							     GList                **result);

LibPolKitResult    libpolkit_is_uid_allowed_for_policy      (LibPolKitContext     *ctx,
							     uid_t                  uid, 
							     const char            *policy, 
							     const char            *resource,
							     gboolean              *result);


LibPolKitResult    libpolkit_is_uid_gid_allowed_for_policy  (LibPolKitContext     *ctx,
							     uid_t                  uid, 
							     guint                  num_gids,
							     gid_t                 *gid_list,
							     const char            *policy, 
							     const char            *resource,
							     gboolean              *result);



LibPolKitResult   libpolkit_get_whitelist                  (LibPolKitContext     *ctx,
							     const char            *policy,
							     GList                **result);

LibPolKitResult   libpolkit_get_blacklist                  (LibPolKitContext     *ctx,
							     const char            *policy,
							     GList                **result);

LibPolKitResult   libpolkit_set_whitelist                  (LibPolKitContext     *ctx,
							     const char            *policy,
							     GList                 *whitelist);

LibPolKitResult   libpolkit_set_blacklist                  (LibPolKitContext     *ctx,
							     const char            *policy,
							     GList                 *blacklist);


LibPolKitElementType   libpolkit_element_get_type          (LibPolKitElement     *elem);

gboolean                libpolkit_element_get_include_all   (LibPolKitElement     *elem);

gboolean                libpolkit_element_get_exclude_all   (LibPolKitElement     *elem);

uid_t                   libpolkit_element_get_uid           (LibPolKitElement     *elem);

gid_t                   libpolkit_element_get_gid           (LibPolKitElement     *elem);

const char             *libpolkit_element_get_resource      (LibPolKitElement     *elem);



LibPolKitElement      *libpolkit_element_new               (LibPolKitContext     *ctx);

void                    libpolkit_element_set_type          (LibPolKitElement     *elem, 
							     LibPolKitElementType  type);

void                    libpolkit_element_set_include_all   (LibPolKitElement     *elem, 
							     gboolean                 value);

void                    libpolkit_element_set_exclude_all   (LibPolKitElement     *elem, 
							     gboolean                 value);

void                    libpolkit_element_set_uid           (LibPolKitElement     *elem, 
							     uid_t                    uid);

void                    libpolkit_element_set_gid           (LibPolKitElement     *elem, 
							     gid_t                    gid);

void                    libpolkit_element_set_resource      (LibPolKitElement     *elem, 
							     const char              *resource);



void                    libpolkit_free_element              (LibPolKitElement     *elem);

void                    libpolkit_free_element_list         (GList *policy_element_list);



char *libpolkit_util_uid_to_name (LibPolKitContext *ctx, uid_t uid, gid_t *default_gid);
char *libpolkit_util_gid_to_name (LibPolKitContext *ctx, gid_t gid);

uid_t libpolkit_util_name_to_uid (LibPolKitContext *ctx, const char *username, gid_t *default_gid);
gid_t libpolkit_util_name_to_gid (LibPolKitContext *ctx, const char *groupname);

void  libpolkit_element_dump     (LibPolKitElement *elem, FILE* fp);

#endif /* LIBPOLKIT_H */



/***************************************************************************
 *
 * libpolkit.c : Simple library for system software to query policy and 
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include "libpolkit.h"


#define LIBPOLKIT_MAGIC 0x3117beef

#ifdef __SUNPRO_C
#define __FUNCTION__ __func__
#endif

#define LIBPOLKIT_CHECK_CONTEXT(_ctx_, _ret_)				\
	do {									\
		if (_ctx_ == NULL) {						\
			g_warning ("%s: given LibPolKitContext is NULL",     \
				   __FUNCTION__);			        \
			return _ret_;					        \
		}								\
		if (_ctx_->magic != LIBPOLKIT_MAGIC) {			\
			g_warning ("%s: given LibPolKitContext is invalid",  \
				   __FUNCTION__);			        \
			return _ret_;					        \
		}								\
	} while(0)


struct LibPolKitContext_s
{
	guint32 magic;
	char *txt_backend_source;
};

struct LibPolKitElement_s
{
	LibPolKitContext *ctx;
	LibPolKitElementType type;
	union {
		uid_t uid;
		gid_t gid;
	} id;
	gboolean include_all;
	gboolean exclude_all;
	char *resource;
};


/** Get a new context.
 *
 *  @return                     Pointer to new context or NULL if an error occured
 */
LibPolKitContext *
libpolkit_new_context (void)
{
	LibPolKitContext *ctx;

	ctx = g_new0 (LibPolKitContext, 1);
	ctx->magic = LIBPOLKIT_MAGIC;
	ctx->txt_backend_source = g_strdup (PACKAGE_SYSCONF_DIR "/PolicyKit/policy");
	return ctx;
}

gboolean
libpolkit_context_set_txt_source (LibPolKitContext   *ctx,
				  const char *directory)
{
	LIBPOLKIT_CHECK_CONTEXT (ctx, FALSE);
	g_free (ctx->txt_backend_source);
	ctx->txt_backend_source = g_strdup (directory);
	return TRUE;
}

/** Free a context
 *
 *  @param  ctx                 The context obtained from libpolkit_new_context
 *  @return                     Pointer to new context or NULL if an error occured
 */
gboolean
libpolkit_free_context (LibPolKitContext *ctx)
{
	LIBPOLKIT_CHECK_CONTEXT (ctx, FALSE);
	ctx->magic = 0;
	g_free (ctx->txt_backend_source);
	g_free (ctx);
	return TRUE;		
}

static LibPolKitResult
txt_backend_read_policy (LibPolKitContext    *ctx,
			 const char             *policy,
			 const char             *key,
			 GList                 **result)
{
	int i;
	GKeyFile *keyfile;
	GError *error;
	LibPolKitResult rc;
	char *path;
	char *value = NULL;
	char **tokens = NULL;
	char *ttype = NULL;
	char *tvalue = NULL;
	char *tresource = NULL;
	LibPolKitElement *elem = NULL;
	GList *res;
	GList *l;
	char *token;

	error = NULL;
	rc = LIBPOLKIT_RESULT_ERROR;
	res = NULL;
	*result = NULL;

	keyfile = g_key_file_new ();
	path = g_strdup_printf ("%s/%s.policy", ctx->txt_backend_source, policy);
	/*g_message ("Loading %s", path);*/
	if (!g_key_file_load_from_file (keyfile, path, G_KEY_FILE_NONE, &error)) {
		g_warning ("Couldn't open key-file '%s': %s", path, error->message);
		g_error_free (error);
		rc = LIBPOLKIT_RESULT_NO_SUCH_POLICY;
		goto out;
	}

	value = g_key_file_get_string (keyfile, "Policy", key, &error);
	if (value == NULL) {
		g_warning ("Cannot get key '%s' in group 'Policy' in file '%s': %s", key, path, error->message);
		g_error_free (error);
		rc = LIBPOLKIT_RESULT_ERROR;
		goto out;
	}

	/*g_message ("value = '%s'", value);*/
	tokens = g_strsplit (value, " ", 0);
	for (i = 0; tokens[i] != NULL; i++) {
		char **components;
		int num_components;

		token = tokens[i];
		/*g_message ("  token = '%s'", token);*/

		ttype = NULL;
		tvalue = NULL;
		tresource = NULL;

		elem = libpolkit_element_new (ctx);

		components = g_strsplit (token, ":", 3);
		num_components = g_strv_length (components);
		if (num_components == 2) {
			ttype = g_strdup (components[0]);
			tvalue = g_strdup (components[1]);
			tresource = NULL;
		} else if (num_components == 3) {
			ttype = g_strdup (components[0]);
			tvalue = g_strdup (components[1]);
			tresource = g_strdup (components[2]);
		} else {
			g_strfreev (components);
			goto malformed_token;
		}
		g_strfreev (components);

		/*g_message ("  type='%s' value='%s' resource='%s'", ttype, tvalue, tresource != NULL ? tresource : "None");*/

		if (strcmp (ttype, "uid") == 0) {
			libpolkit_element_set_type (elem, LIBPOLKIT_ELEMENT_TYPE_UID);
			if (strcmp (tvalue, "__all__") == 0) {
				libpolkit_element_set_include_all (elem, TRUE);
			} else if (strcmp (tvalue, "__none__") == 0) {
				libpolkit_element_set_exclude_all (elem, TRUE);
			} else {
				uid_t uid;
				char *endp;
				uid = (uid_t) g_ascii_strtoull (tvalue, &endp, 0);
				if (endp[0] != '\0') {
					uid = libpolkit_util_name_to_uid (ctx, tvalue, NULL);
					if (uid == (uid_t) -1) {
						g_warning ("User '%s' does not exist", tvalue);
						goto malformed_token;
					}
				}
				libpolkit_element_set_uid (elem, uid);
			}
		} else if (strcmp (ttype, "gid") == 0) {
			libpolkit_element_set_type (elem, LIBPOLKIT_ELEMENT_TYPE_GID);
			if (strcmp (tvalue, "__all__") == 0) {
				libpolkit_element_set_include_all (elem, TRUE);
			} else if (strcmp (tvalue, "__none__") == 0) {
				libpolkit_element_set_exclude_all (elem, TRUE);
			} else {
				gid_t gid;
				char *endp;
				gid = (gid_t) g_ascii_strtoull (tvalue, &endp, 0);
				if (endp[0] != '\0') {
					gid = libpolkit_util_name_to_gid (ctx, tvalue);
					if (gid == (gid_t) -1) {
						g_warning ("Group '%s' does not exist", tvalue);
						goto malformed_token;
					}
				}
				libpolkit_element_set_gid (elem, gid);
			}
		} else {
			g_warning ("Token '%s' in key '%s' in group 'Policy' in file '%s' malformed",
				   token, key, path);
			goto malformed_token;
		}

		if (tresource != NULL) {
			libpolkit_element_set_resource (elem, tresource);
		}

		g_free (ttype);
		g_free (tvalue);
		g_free (tresource);

		res = g_list_append (res, elem);
		/*libpolkit_element_dump (elem, stderr);*/

	}

	*result = res;
	rc = LIBPOLKIT_RESULT_OK;
	goto out;

malformed_token:
	g_warning ("Token '%s' in key '%s' in group 'Policy' in file '%s' malformed", token, key, path);

	for (l = res; l != NULL; l = g_list_next (l)) {
		libpolkit_free_element ((LibPolKitElement *) l->data);
	}
	g_list_free (res);
	libpolkit_free_element (elem);
	g_free (ttype);
	g_free (tvalue);
	g_free (tresource);

out:
	g_strfreev (tokens);
	g_free (value);

	g_key_file_free (keyfile);
	g_free (path);

	return rc;
}

static void
afp_process_elem(LibPolKitElement *elem, gboolean *flag, uid_t uid, guint num_gids, gid_t *gid_list)
{
	/*libpolkit_element_dump (elem, stderr);*/

	switch (elem->type) {
	case LIBPOLKIT_ELEMENT_TYPE_UID:
		if (elem->include_all) {
			*flag = TRUE;
		} else if (elem->exclude_all) {
			*flag = FALSE;
		}else {
			if (elem->id.uid == uid)
				*flag = TRUE;
		}
		break;
		
	case LIBPOLKIT_ELEMENT_TYPE_GID:
		if (elem->include_all) {
			*flag = TRUE;
		} else if (elem->exclude_all) {
			*flag = FALSE;
		}else {
			guint i;
			for (i = 0; i < num_gids; i++) {
				if (elem->id.gid == gid_list[i])
					*flag = TRUE;
			}
		}
		break;
	}
}

LibPolKitResult 
libpolkit_is_uid_gid_allowed_for_policy (LibPolKitContext    *ctx,
					 uid_t                 uid, 
					 guint                 num_gids,
					 gid_t                *gid_list,
					 const char           *policy, 
					 const char           *resource,
					 gboolean             *result)
{
	gboolean is_in_whitelist;
	gboolean is_in_blacklist;
	GList *l;
	GList *whitelist;
	GList *blacklist;
	LibPolKitResult res;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	whitelist = NULL;
	blacklist = NULL;
	res = LIBPOLKIT_RESULT_ERROR;

	res = libpolkit_get_whitelist (ctx, policy, &whitelist);
	if (res != LIBPOLKIT_RESULT_OK)
		goto out;

	res = libpolkit_get_blacklist (ctx, policy, &blacklist);
	if (res != LIBPOLKIT_RESULT_OK)
		goto out;

	is_in_whitelist = FALSE;
	is_in_blacklist = FALSE;

	/*  Algorithm: To succeed.. we must be in the whitelist.. and not in the blacklist */

	for (l = whitelist; l != NULL; l = g_list_next (l)) {
		LibPolKitElement *elem;
		elem = (LibPolKitElement *) l->data;
		if ((elem->resource == NULL) ||
		    ((resource != NULL) && (strcmp (elem->resource, resource) == 0))) {
			afp_process_elem (elem, &is_in_whitelist, uid, num_gids, gid_list);
		}
	}

	for (l = blacklist; l != NULL; l = g_list_next (l)) {
		LibPolKitElement *elem;
		elem = (LibPolKitElement *) l->data;
		if ((elem->resource == NULL) ||
		    ((resource != NULL) && (strcmp (elem->resource, resource) == 0))) {
			afp_process_elem (elem, &is_in_blacklist, uid, num_gids, gid_list);
		}
	}

	*result =  is_in_whitelist && (!is_in_blacklist);

	res = LIBPOLKIT_RESULT_OK;

out:
	if (whitelist != NULL)
		libpolkit_free_element_list (whitelist);
	if (blacklist != NULL)
		libpolkit_free_element_list (blacklist);

	return res;	
}

char *
libpolkit_util_uid_to_name (LibPolKitContext *ctx, uid_t uid, gid_t *default_gid)
{
	int rc;
	char *res;
	char *buf = NULL;
	unsigned int bufsize;
	struct passwd pwd;
	struct passwd *pwdp;

	LIBPOLKIT_CHECK_CONTEXT (ctx, NULL);

	res = NULL;

	bufsize = sysconf (_SC_GETPW_R_SIZE_MAX);
	buf = g_new0 (char, bufsize);

	rc = getpwuid_r (uid, &pwd, buf, bufsize, &pwdp);
	if (rc != 0 || pwdp == NULL) {
		/*g_warning ("getpwuid_r() returned %d", rc);*/
		goto out;
	}

	res = g_strdup (pwdp->pw_name);
	if (default_gid != NULL)
		*default_gid = pwdp->pw_gid;

out:
	g_free (buf);
	return res;
}

char *
libpolkit_util_gid_to_name (LibPolKitContext *ctx, gid_t gid)
{
	int rc;
	char *res;
	char *buf = NULL;
	unsigned int bufsize;
	struct group gbuf;
	struct group *gbufp;

	LIBPOLKIT_CHECK_CONTEXT (ctx, NULL);

	res = NULL;

	bufsize = sysconf (_SC_GETGR_R_SIZE_MAX);
	buf = g_new0 (char, bufsize);
		
	rc = getgrgid_r (gid, &gbuf, buf, bufsize, &gbufp);
	if (rc != 0 || gbufp == NULL) {
		/*g_warning ("getgrgid_r() returned %d", rc);*/
		goto out;
	}

	res = g_strdup (gbufp->gr_name);

out:
	g_free (buf);
	return res;
}



uid_t
libpolkit_util_name_to_uid (LibPolKitContext *ctx, const char *username, gid_t *default_gid)
{
	int rc;
	uid_t res;
	char *buf = NULL;
	unsigned int bufsize;
	struct passwd pwd;
	struct passwd *pwdp;

	LIBPOLKIT_CHECK_CONTEXT (ctx, (uid_t) -1);

	res = (uid_t) -1;

	bufsize = sysconf (_SC_GETPW_R_SIZE_MAX);
	buf = g_new0 (char, bufsize);
		
	rc = getpwnam_r (username, &pwd, buf, bufsize, &pwdp);
	if (rc != 0 || pwdp == NULL) {
		/*g_warning ("getpwnam_r() returned %d", rc);*/
		goto out;
	}

	res = pwdp->pw_uid;
	if (default_gid != NULL)
		*default_gid = pwdp->pw_gid;

out:
	g_free (buf);
	return res;
}

gid_t 
libpolkit_util_name_to_gid (LibPolKitContext *ctx, const char *groupname)
{
	int rc;
	gid_t res;
	char *buf = NULL;
	unsigned int bufsize;
	struct group gbuf;
	struct group *gbufp;

	LIBPOLKIT_CHECK_CONTEXT (ctx, (gid_t) -1);

	res = (gid_t) -1;

	bufsize = sysconf (_SC_GETGR_R_SIZE_MAX);
	buf = g_new0 (char, bufsize);
		
	rc = getgrnam_r (groupname, &gbuf, buf, bufsize, &gbufp);
	if (rc != 0 || gbufp == NULL) {
		/*g_warning ("getgrnam_r() returned %d", rc);*/
		goto out;
	}

	res = gbufp->gr_gid;

out:
	g_free (buf);
	return res;
}


LibPolKitResult 
libpolkit_is_uid_allowed_for_policy (LibPolKitContext    *ctx,
				     uid_t                 uid, 
				     const char           *policy, 
				     const char           *resource,
				     gboolean             *result)
{
	int num_groups = 0;
	gid_t *groups = NULL;
	char *username;
	gid_t default_gid;
	LibPolKitResult  r;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	r = LIBPOLKIT_RESULT_ERROR;

	if ((username = libpolkit_util_uid_to_name (ctx, uid, &default_gid)) == NULL)
		goto out;

	/* TODO: this is glibc only at the moment... */
	if (getgrouplist(username, default_gid, NULL, &num_groups) < 0) {
		groups = (gid_t *) g_new0 (gid_t, num_groups);
		if (getgrouplist(username, default_gid, groups, &num_groups) < 0) {
			g_warning ("getgrouplist() failed");
			goto out;
		}
	}

	/*
	{
		int i;
		g_debug ("uid %d (%s)", uid, username);
		for (i = 0; i < num_groups; i++) {
			char *group_name;
			group_name = libpolkit_util_gid_to_name (groups[i]);
			g_debug ("  gid %d (%s)", groups[i], group_name);
			g_free (group_name);
		}
	}
	*/

	r = libpolkit_is_uid_gid_allowed_for_policy (ctx,
							 uid,
							 num_groups,
							 groups,
							 policy,
							 resource,
							 result);

out:
	g_free (username);
	g_free (groups);
	return r;
}


/** Return all elements in the white-list for a policy
 *
 *  @param  ctx                 The context obtained from libpolkit_new_context
 *  @param  policy              Name of policy
 *  @param  results             On success set to a list of dynamically allocated LibPolKitElement structures. 
 *                              Must be freed by the caller
 *  @return                     Whether the operation succeeded
 */
LibPolKitResult
libpolkit_get_whitelist (LibPolKitContext    *ctx,
			 const char           *policy,
			 GList               **result)
{
	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	return txt_backend_read_policy (ctx, policy, "Allow", result);
}

/** Return all elements in the black-list for a policy
 *
 *  @param  ctx                 The context obtained from libpolkit_new_context
 *  @param  policy              Name of policy
 *  @param  results             On success set to a list of dynamically allocated LibPolKitElement structures. 
 *                              Must be freed by the caller
 *  @return                     Whether the operation succeeded
 */
LibPolKitResult
libpolkit_get_blacklist (LibPolKitContext    *ctx,
			 const char           *policy,
			 GList               **result)
{
	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	return txt_backend_read_policy (ctx, policy, "Deny", result);
}

/** Return all elements in the white-list for a policy
 *
 *  @param  ctx                 The context obtained from libpolkit_new_context
 *  @param  result              On success set to a list of dynamically allocated strings. 
 *                              Must be freed by the caller.
 *  @return                     Whether the operation succeeded
 */
LibPolKitResult
libpolkit_get_policies (LibPolKitContext   *ctx,
			GList              **result)
{
	GDir *dir;
	GError *error;
	const char *f;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	error = NULL;
	*result = NULL;

	if ((dir = g_dir_open (ctx->txt_backend_source, 0, &error)) == NULL) {
		g_critical ("Unable to open %s: %s", ctx->txt_backend_source, error->message);
		g_error_free (error);
		goto error;
	}
	while ((f = g_dir_read_name (dir)) != NULL) {
		if (g_str_has_suffix (f, ".policy")) {
			char *s;
			int pos;
			
			s = g_strdup (f);
			pos = strlen (s) - 7;
			if (pos > 0)
				s[pos] = '\0';

			*result = g_list_append (*result, s);
		}
	}
	
	g_dir_close (dir);

	return LIBPOLKIT_RESULT_OK;

error:
	return LIBPOLKIT_RESULT_ERROR;
}


LibPolKitElement *
libpolkit_element_new (LibPolKitContext *ctx)
{
	LibPolKitElement *elem;

	LIBPOLKIT_CHECK_CONTEXT (ctx, NULL);

	elem = g_new0 (LibPolKitElement, 1);
	elem->ctx = ctx;
	return elem;
}

void 
libpolkit_element_set_type (LibPolKitElement *elem, 
			    LibPolKitElementType type)
{
	elem->type = type;
}

void
libpolkit_element_set_include_all (LibPolKitElement     *elem, 
				   gboolean                 value)
{
	elem->include_all = value;
}

void
libpolkit_element_set_exclude_all (LibPolKitElement     *elem, 
				   gboolean                 value)
{
	elem->exclude_all = value;
}

void
libpolkit_element_set_uid (LibPolKitElement     *elem, 
			   uid_t                    uid)
{
	elem->id.uid = uid;
}

void
libpolkit_element_set_gid (LibPolKitElement     *elem, 
			   gid_t                    gid)
{
	elem->id.gid = gid;
}

void
libpolkit_element_set_resource (LibPolKitElement     *elem, 
				const char              *resource)
{
	g_free (elem->resource);
	elem->resource = g_strdup (resource);
}



void
libpolkit_free_element (LibPolKitElement     *elem)
{
	g_free (elem->resource);
	g_free (elem);
}

void 
libpolkit_free_element_list (GList *policy_element_list)
{
	GList *l;

	for (l = policy_element_list; l != NULL; l = g_list_next (l)) {
		LibPolKitElement *elem = (LibPolKitElement *) l->data;
		libpolkit_free_element (elem);
	}

	g_list_free (policy_element_list);
}

LibPolKitElementType
libpolkit_element_get_type (LibPolKitElement     *elem)
{
	return elem->type;
}

gboolean 
libpolkit_element_get_include_all (LibPolKitElement     *elem)
{
	return elem->include_all;
}

gboolean 
libpolkit_element_get_exclude_all (LibPolKitElement     *elem)
{
	return elem->exclude_all;
}

uid_t
libpolkit_element_get_uid (LibPolKitElement     *elem)
{
	return elem->id.uid;
}

gid_t
libpolkit_element_get_gid (LibPolKitElement     *elem)
{
	return elem->id.gid;
}

const char *
libpolkit_element_get_resource (LibPolKitElement     *elem)
{
	return elem->resource;
}

void
libpolkit_element_dump (LibPolKitElement *elem, FILE* fp)
{
	char *t;

	if (elem->type == LIBPOLKIT_ELEMENT_TYPE_UID)
		t = "uid";
	else if (elem->type == LIBPOLKIT_ELEMENT_TYPE_GID)
		t = "gid";
	else
		t = "(Unknown)";

	fprintf (fp, "type:     %s\n", t);
	if (elem->type == LIBPOLKIT_ELEMENT_TYPE_UID) {
		if (elem->include_all) {
			fprintf (fp, "uid:      all\n");
		} else if (elem->exclude_all) {
			fprintf (fp, "uid:      none\n");
		} else {
			fprintf (fp, "uid:      %d\n", (int) elem->id.uid);
		}
	} else if (elem->type == LIBPOLKIT_ELEMENT_TYPE_GID) {
		if (elem->include_all) {
			fprintf (fp, "gid:      all\n");
		} else if (elem->exclude_all) {
			fprintf (fp, "gid:      none\n");
		} else {
			fprintf (fp, "gid:      %d\n", (int) elem->id.gid);
		}
	}
	fprintf (fp, "resource: %s\n", elem->resource != NULL ? elem->resource : "(None)");
}

#ifndef HAVE_GETGROUPLIST
/* Get group list for the named user.
 * Return up to ngroups in the groups array.
 * Return actual number of groups in ngroups.
 * Return -1 if more groups found than requested.
 */
int
getgrouplist (const char *name, int baseid, int *groups, int *ngroups)
{
	struct group *g;
	int n = 0;
	int i;
	int ret;

	if (*ngroups <= 0) {
		return (-1);
	}

	*groups++ = baseid;
	n++;

	setgrent ();
	while ((g = getgrent ()) != NULL) {
		for (i = 0; g->gr_mem[i]; i++) {
			if (strcmp (name, g->gr_mem[0]) == 0) {
				*groups++ = g->gr_gid;
				if (++n > *ngroups) {
					break;
				}
			}
		}
	}
	endgrent ();

	ret = (n > *ngroups) ? -1 : n;
	*ngroups = n;
	return (ret);
}
#endif

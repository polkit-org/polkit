/***************************************************************************
 * CVSID: $Id$
 *
 * policy.c : Wraps policy
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

#include "policy.h"

#ifdef __SUNPRO_C
#define __FUNCTION__ __func__
#endif

static char *policy_directory = PACKAGE_SYSCONF_DIR "/PolicyKit/privilege.d";

void
policy_util_set_policy_directory (const char *directory)
{
	policy_directory = g_strdup (directory);
}


typedef enum {
	POLICY_ELEMENT_TYPE_UID,
	POLICY_ELEMENT_TYPE_GID
} PolicyElementType;


struct PolicyElement_s
{
	PolicyElementType type;
	union {
		uid_t uid;
		gid_t gid;
	} id;
	gboolean include_all;
	gboolean exclude_all;
	char *resource;
};

typedef struct PolicyElement_s PolicyElement;

static PolicyElement *
policy_element_new (void)
{
	PolicyElement *elem;

	elem = g_new0 (PolicyElement, 1);
	return elem;
}

static void
policy_element_free (PolicyElement *elem)
{
	g_free (elem->resource);
	g_free (elem);
}

static void 
policy_element_free_list (GList *policy_element_list)
{
	GList *l;

	for (l = policy_element_list; l != NULL; l = g_list_next (l)) {
		PolicyElement *elem = (PolicyElement *) l->data;
		policy_element_free (elem);
	}

	g_list_free (policy_element_list);
}

#if 0
static void
policy_element_dump (PolicyElement *elem, FILE* fp)
{
	char *t;

	if (elem->type == POLICY_ELEMENT_TYPE_UID)
		t = "uid";
	else if (elem->type == POLICY_ELEMENT_TYPE_GID)
		t = "gid";
	else
		t = "(Unknown)";

	fprintf (fp, "type:     %s\n", t);
	if (elem->type == POLICY_ELEMENT_TYPE_UID) {
		if (elem->include_all) {
			fprintf (fp, "uid:      all\n");
		} else if (elem->exclude_all) {
			fprintf (fp, "uid:      none\n");
		} else {
			fprintf (fp, "uid:      %d\n", (int) elem->id.uid);
		}
	} else if (elem->type == POLICY_ELEMENT_TYPE_GID) {
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
#endif


static PolicyResult
txt_backend_read_policy (const char             *policy,
			 const char             *key,
			 GList                 **result)
{
	int i;
	GKeyFile *keyfile;
	GError *error;
	PolicyResult rc;
	char *path;
	char *value = NULL;
	char **tokens = NULL;
	char *ttype = NULL;
	char *tvalue = NULL;
	char *tresource = NULL;
	PolicyElement *elem = NULL;
	GList *res;
	GList *l;
	char *token;

	error = NULL;
	rc = POLICY_RESULT_ERROR;
	res = NULL;
	*result = NULL;

	keyfile = g_key_file_new ();
	path = g_strdup_printf ("%s/%s.privilege", policy_directory, policy);
	/*g_message ("Loading %s", path);*/
	if (!g_key_file_load_from_file (keyfile, path, G_KEY_FILE_NONE, &error)) {
		g_warning ("Couldn't open key-file '%s': %s", path, error->message);
		g_error_free (error);
		rc = POLICY_RESULT_NO_SUCH_POLICY;
		goto out;
	}

	value = g_key_file_get_string (keyfile, "Privilege", key, &error);
	if (value == NULL) {
		g_warning ("Cannot get key '%s' in group 'Policy' in file '%s': %s", key, path, error->message);
		g_error_free (error);
		rc = POLICY_RESULT_ERROR;
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

		elem = policy_element_new ();

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
			elem->type = POLICY_ELEMENT_TYPE_UID;
			if (strcmp (tvalue, "__all__") == 0) {
				elem->include_all = TRUE;
			} else if (strcmp (tvalue, "__none__") == 0) {
				elem->exclude_all = TRUE;
			} else {
				uid_t uid;
				char *endp;
				uid = (uid_t) g_ascii_strtoull (tvalue, &endp, 0);
				if (endp[0] != '\0') {
					uid = policy_util_name_to_uid (tvalue, NULL);
					if (uid == (uid_t) -1) {
						g_warning ("User '%s' does not exist", tvalue);
						goto malformed_token;
					}
				}
				elem->id.uid = uid;
			}
		} else if (strcmp (ttype, "gid") == 0) {
			elem->type = POLICY_ELEMENT_TYPE_GID;
			if (strcmp (tvalue, "__all__") == 0) {
				elem->include_all = TRUE;
			} else if (strcmp (tvalue, "__none__") == 0) {
				elem->exclude_all = TRUE;
			} else {
				gid_t gid;
				char *endp;
				gid = (gid_t) g_ascii_strtoull (tvalue, &endp, 0);
				if (endp[0] != '\0') {
					gid = policy_util_name_to_gid (tvalue);
					if (gid == (gid_t) -1) {
						g_warning ("Group '%s' does not exist", tvalue);
						goto malformed_token;
					}
				}
				elem->id.gid = gid;
			}
		} else {
			g_warning ("Token '%s' in key '%s' in group 'Policy' in file '%s' malformed",
				   token, key, path);
			goto malformed_token;
		}

		if (tresource != NULL) {
			elem->resource = g_strdup (tresource);
		}

		g_free (ttype);
		g_free (tvalue);
		g_free (tresource);

		res = g_list_append (res, elem);
		/*policy_element_dump (elem, stderr);*/

	}

	*result = res;
	rc = POLICY_RESULT_OK;
	goto out;

malformed_token:
	g_warning ("Token '%s' in key '%s' in group 'Policy' in file '%s' malformed", token, key, path);

	for (l = res; l != NULL; l = g_list_next (l)) {
		policy_element_free ((PolicyElement *) l->data);
	}
	g_list_free (res);
	policy_element_free (elem);
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


static PolicyResult
txt_backend_read_list (const char             *policy,
		       const char             *key,
		       GList                 **result)
{
	int i;
	GKeyFile *keyfile;
	GError *error;
	PolicyResult rc;
	char *path;
	char *value = NULL;
	char **tokens = NULL;
	GList *res;
	char *token;

	error = NULL;
	rc = POLICY_RESULT_ERROR;
	res = NULL;
	*result = NULL;

	keyfile = g_key_file_new ();
	path = g_strdup_printf ("%s/%s.privilege", policy_directory, policy);
	/*g_message ("Loading %s", path);*/
	if (!g_key_file_load_from_file (keyfile, path, G_KEY_FILE_NONE, &error)) {
		g_warning ("Couldn't open key-file '%s': %s", path, error->message);
		g_error_free (error);
		rc = POLICY_RESULT_NO_SUCH_POLICY;
		goto out;
	}

	value = g_key_file_get_string (keyfile, "Privilege", key, &error);
	if (value == NULL) {
		g_warning ("Cannot get key '%s' in group 'Policy' in file '%s': %s", key, path, error->message);
		g_error_free (error);
		rc = POLICY_RESULT_ERROR;
		goto out;
	}

	/*g_message ("value = '%s'", value);*/
	tokens = g_strsplit (value, " ", 0);
	for (i = 0; tokens[i] != NULL; i++) {
		token = tokens[i];
		/*g_message ("  token = '%s'", token);*/

		res = g_list_append (res, g_strdup (token));
	}

	*result = res;
	rc = POLICY_RESULT_OK;

out:
	g_strfreev (tokens);
	g_free (value);

	g_key_file_free (keyfile);
	g_free (path);

	return rc;
}

static PolicyResult
txt_backend_read_word (const char             *policy,
		       const char             *key,
		       char                  **result)
{
	GKeyFile *keyfile;
	GError *error;
	PolicyResult rc;
	char *path;
	char *value = NULL;

	error = NULL;
	rc = POLICY_RESULT_ERROR;
	*result = NULL;

	keyfile = g_key_file_new ();
	path = g_strdup_printf ("%s/%s.privilege", policy_directory, policy);
	/*g_message ("Loading %s", path);*/
	if (!g_key_file_load_from_file (keyfile, path, G_KEY_FILE_NONE, &error)) {
		g_warning ("Couldn't open key-file '%s': %s", path, error->message);
		g_error_free (error);
		rc = POLICY_RESULT_NO_SUCH_POLICY;
		goto out;
	}

	value = g_key_file_get_string (keyfile, "Privilege", key, &error);
	if (value == NULL) {
		g_warning ("Cannot get key '%s' in group 'Policy' in file '%s': %s", key, path, error->message);
		g_error_free (error);
		rc = POLICY_RESULT_ERROR;
		goto out;
	}

	/*g_message ("value = '%s'", value);*/

	*result = g_strdup (value);

	rc = POLICY_RESULT_OK;

out:
	g_free (value);

	g_key_file_free (keyfile);
	g_free (path);

	return rc;
}

static PolicyResult
policy_get_whitelist (const char           *policy,
		      GList               **result)
{
	return txt_backend_read_policy (policy, "Allow", result);
}

static PolicyResult
policy_get_blacklist (const char           *policy,
		      GList               **result)
{
	return txt_backend_read_policy (policy, "Deny", result);
}

static PolicyResult
policy_get_sufficient_privileges (const char           *policy,
				  GList               **result)
{
	return txt_backend_read_list (policy, "SufficientPrivileges", result);
}

static PolicyResult
policy_get_required_privileges (const char           *policy,
				GList               **result)
{
	return txt_backend_read_list (policy, "RequiredPrivileges", result);
}

/** Return all elements in the white-list for a policy
 *
 *  @param  result              On success set to a list of dynamically allocated strings. 
 *                              Must be freed by the caller.
 *  @return                     Whether the operation succeeded
 */
PolicyResult
policy_get_policies (GList              **result)
{
	GDir *dir;
	GError *error;
	const char *f;

	error = NULL;
	*result = NULL;

	if ((dir = g_dir_open (policy_directory, 0, &error)) == NULL) {
		g_critical ("Unable to open %s: %s", policy_directory, error->message);
		g_error_free (error);
		goto error;
	}
	while ((f = g_dir_read_name (dir)) != NULL) {
		if (g_str_has_suffix (f, ".privilege")) {
			char *s;
			int pos;
			
			s = g_strdup (f);
			pos = strlen (s) - 10; /* .privilege - 10 chars */
			if (pos > 0)
				s[pos] = '\0';

			*result = g_list_append (*result, s);
		}
	}
	
	g_dir_close (dir);

	return POLICY_RESULT_OK;

error:
	return POLICY_RESULT_ERROR;
}

PolicyResult 
policy_get_auth_details_for_policy (uid_t           uid,
				    const char     *policy,
				    const char     *resource,
				    gboolean       *out_auth_can_obtain,
				    gboolean       *out_auth_can_obtain_is_temporary,
				    gboolean       *out_auth_can_grant,
				    gboolean       *out_auth_obtain_requires_root,
				    gpointer        have_temp_privilege_userdata,
				    HaveTempPrivCB  have_temp_privilege)
{
	PolicyResult res;
	GList *required_privs;
	GList *l;
	char *can_obtain_word;
	char *can_grant_word;
	char *obtain_requires_root_word;

	required_privs = NULL;
	can_obtain_word = NULL;
	can_grant_word = NULL;

	*out_auth_can_obtain = FALSE;
	*out_auth_can_obtain_is_temporary = FALSE;
	*out_auth_can_grant = FALSE;
	*out_auth_obtain_requires_root = TRUE;

	res = POLICY_RESULT_ERROR;

	res = txt_backend_read_word (policy, "CanObtain", &can_obtain_word);
	if (res != POLICY_RESULT_OK)
		goto out;

	res = txt_backend_read_word (policy, "CanGrant", &can_grant_word);
	if (res != POLICY_RESULT_OK)
		goto out;

	res = txt_backend_read_word (policy, "ObtainRequireRoot", &obtain_requires_root_word);
	if (res != POLICY_RESULT_OK)
		goto out;

	if (strcmp (can_obtain_word, "True") == 0) {
		*out_auth_can_obtain = TRUE;
		*out_auth_can_obtain_is_temporary = FALSE;
	} else if (strcmp (can_obtain_word, "False") == 0) {
		*out_auth_can_obtain = FALSE;
		*out_auth_can_obtain_is_temporary = FALSE;
	} else if (strcmp (can_obtain_word, "Temporary") == 0) {
		*out_auth_can_obtain = TRUE;
		*out_auth_can_obtain_is_temporary = TRUE;
	} else {
		g_critical ("CanObtain has bogus value '%s' in privilege '%s'",
			    can_obtain_word, policy);
		goto out;
	}

	if (strcmp (can_grant_word, "True") == 0) {
		*out_auth_can_grant = TRUE;
	} else if (strcmp (can_grant_word, "False") == 0) {
		*out_auth_can_grant = FALSE;
	} else {
		g_critical ("CanGrant has bogus value '%s' in privilege '%s'",
			    can_grant_word, policy);
		goto out;
	}

	if (strcmp (obtain_requires_root_word, "True") == 0) {
		*out_auth_obtain_requires_root = TRUE;
	} else if (strcmp (obtain_requires_root_word, "False") == 0) {
		*out_auth_obtain_requires_root = FALSE;
	} else {
		g_critical ("ObtainRequireRoot has bogus value '%s' in privilege '%s'",
			    obtain_requires_root_word, policy);
		goto out;
	}

	/* no need to check RequiredPrivileges if said privilege says we can't obtain it */
	if ((*out_auth_can_obtain) == FALSE)
		goto determined;

	/* if privilege already requires super user, no need to check RequiredPrivileges */
	if ((*out_auth_obtain_requires_root) == TRUE)
		goto determined;

	/* So now the user can obtain the privilege and doesn't
	 * require root. However, per the spec, if he is lacking any
	 * of the privileges listed and one or more of these have
	 *
	 *  - has ObtainRequiresRoot set to TRUE; or
	 *
	 *  - has CanObtain set to FALSE
	 *
	 * then effectively ObtainsRequireRoot becomes TRUE.
	 */

	res = policy_get_required_privileges (policy, &required_privs);
	if (res != POLICY_RESULT_OK)
		goto out;

	g_message ("  * obtain_requires_root = %d", *out_auth_obtain_requires_root);

	for (l = required_privs; l != NULL; l = g_list_next (l)) {
		gboolean has_required_privilege = FALSE;
		gboolean has_required_privilege_is_temp = FALSE;
		char *has_required_privilege_is_restricted = NULL;
		const char *required_privilege = (const char *) l->data;
		PolicyResult res2;

		g_message ("  checking for required privilege  '%s'", required_privilege);

		has_required_privilege = FALSE;
		res2 = policy_is_uid_allowed_for_policy (uid,
							 required_privilege, 
							 NULL, 
							 &has_required_privilege,
							 &has_required_privilege_is_temp,
							 &has_required_privilege_is_restricted,
							 have_temp_privilege_userdata,
							 have_temp_privilege);
		if (res2 != POLICY_RESULT_OK)
			goto out;

		g_message ("   has_required_privilege = %d", has_required_privilege);

		if (!has_required_privilege || 
		    (has_required_privilege && has_required_privilege_is_restricted != NULL)) {

			g_free (can_obtain_word);
			g_free (can_grant_word);
			can_obtain_word = NULL;
			can_grant_word = NULL;

			res = txt_backend_read_word (required_privilege, "CanObtain", 
						     &can_obtain_word);
			if (res != POLICY_RESULT_OK)
				goto out;

			res = txt_backend_read_word (required_privilege, "ObtainRequireRoot", 
						     &obtain_requires_root_word);
			if (res != POLICY_RESULT_OK)
				goto out;

			if (strcmp (can_obtain_word, "False") == 0) {
				*out_auth_obtain_requires_root = TRUE;
				goto determined;
			}

			if (strcmp (obtain_requires_root_word, "True") == 0) {
				*out_auth_obtain_requires_root = TRUE;
				goto determined;
			}
		}
	}
		
determined:
	g_message ("  ** obtain_requires_root = %d", *out_auth_obtain_requires_root);
	res = POLICY_RESULT_OK;

out:
	if (required_privs != NULL) {
		g_list_foreach (required_privs, (GFunc) g_free, NULL);
		g_list_free (required_privs);
	}

	g_free (can_obtain_word);
	g_free (can_grant_word);

	return res;
}



static void
afp_process_elem(PolicyElement *elem, gboolean *flag, uid_t uid, guint num_gids, gid_t *gid_list)
{
	/*policy_element_dump (elem, stderr);*/

	switch (elem->type) {
	case POLICY_ELEMENT_TYPE_UID:
		if (elem->include_all) {
			*flag = TRUE;
		} else if (elem->exclude_all) {
			*flag = FALSE;
		}else {
			if (elem->id.uid == uid)
				*flag = TRUE;
		}
		break;
		
	case POLICY_ELEMENT_TYPE_GID:
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

PolicyResult
policy_get_allowed_resources_for_policy_for_uid_gid  (uid_t                  uid, 
						      guint                  num_gids,
						      gid_t                 *gid_list,
						      const char            *policy, 
						      GList                **result)
{
	GList *l;
	GList *whitelist;
	GList *blacklist;
	gboolean is_in_whitelist;
	gboolean is_in_blacklist;
	PolicyResult res;

	whitelist = NULL;
	blacklist = NULL;
	*result = NULL;
	res = POLICY_RESULT_ERROR;

	res = policy_get_whitelist (policy, &whitelist);
	if (res != POLICY_RESULT_OK)
		goto out;

	res = policy_get_blacklist (policy, &blacklist);
	if (res != POLICY_RESULT_OK)
		goto out;

	is_in_whitelist = FALSE;
	is_in_blacklist = FALSE;

	/*  Algorithm: check each resource in whitelist; 
	 *               if allowed, check against blacklist.. 
	 *                 if not in blacklist, push to results  
	 */

	for (l = whitelist; l != NULL; l = g_list_next (l)) {
		PolicyElement *elem;
		gboolean in_whitelist;
		elem = (PolicyElement *) l->data;

		if (elem->resource != NULL) {
			/* check if we're allowed for this resource */
			afp_process_elem (elem, &in_whitelist, uid, num_gids, gid_list);
			if (in_whitelist) {
				GList *j;
				gboolean in_blacklist;

				/* in whitelist.. yes.. now check if this resource is in the black list*/

				in_blacklist = FALSE;

				for (j = blacklist; j != NULL; j = g_list_next (j)) {
					PolicyElement *elem2;
					elem2 = (PolicyElement *) j->data;

					if (elem2->resource != NULL && 
					    strcmp (elem->resource, elem2->resource) == 0) {
						afp_process_elem (elem2, &in_blacklist, uid, num_gids, gid_list);
						if (in_blacklist)
							break;
					}
				}

				if (in_whitelist && !in_blacklist)
					*result = g_list_append (*result, g_strdup (elem->resource));
			}
		}
	}


	res = POLICY_RESULT_OK;

out:
	if (whitelist != NULL)
		policy_element_free_list (whitelist);
	if (blacklist != NULL)
		policy_element_free_list (blacklist);

	return res;	
}

static PolicyResult 
_policy_is_uid_gid_allowed_for_policy (uid_t           uid, 
				       guint           num_gids,
				       gid_t          *gid_list,
				       const char     *policy, 
				       const char     *resource,
				       gboolean       *out_is_privileged,
				       gboolean       *out_is_temporary,
				       char          **out_is_privileged_but_restricted,
				       gpointer        have_temp_privilege_userdata,
				       HaveTempPrivCB  have_temp_privilege,
				       int             recursion_counter)
{
	gboolean is_in_whitelist;
	gboolean is_in_blacklist;
	GList *l;
	GList *whitelist;
	GList *blacklist;
	GList *sufficient_privs;
	GList *required_privs;
	PolicyResult res;
	PolicyResult res2;

	whitelist = NULL;
	blacklist = NULL;
	sufficient_privs = NULL;
	required_privs = NULL;
	res = POLICY_RESULT_ERROR;

	*out_is_privileged = FALSE;
	*out_is_temporary = FALSE;
	*out_is_privileged_but_restricted = NULL;

	if (recursion_counter > 8) {
		g_critical ("Maximal (8) recursion depth detected checking privilege '%s'", policy);
		goto out;
	}

	res = policy_get_sufficient_privileges (policy, &sufficient_privs);
	if (res != POLICY_RESULT_OK)
		goto out;

	/* first check SufficientPrivileges.. if we have one of those, then return TRUE */
	for (l = sufficient_privs; l != NULL; l = g_list_next (l)) {
		gboolean has_sufficient_privilege = FALSE;
		gboolean has_sufficient_privilege_is_temp = FALSE;
		char *has_sufficient_privilege_is_restricted = NULL;
		const char *sufficient_privilege = (const char *) l->data;

		g_message ("  checking for sufficient privilege  '%s'", sufficient_privilege);

		has_sufficient_privilege = FALSE;
		res2 = _policy_is_uid_gid_allowed_for_policy (uid, num_gids, gid_list, 
							      sufficient_privilege, NULL, 
							      &has_sufficient_privilege,
							      &has_sufficient_privilege_is_temp,
							      &has_sufficient_privilege_is_restricted,
							      have_temp_privilege_userdata,
							      have_temp_privilege, recursion_counter + 1);
		if (res2 != POLICY_RESULT_OK)
			goto out;

		if (has_sufficient_privilege && has_sufficient_privilege_is_restricted == NULL) {
			g_message ("Returned TRUE because we have the sufficient privilege '%s' for privilege '%s'",
				   sufficient_privilege, policy);
			res = POLICY_RESULT_OK;
			*out_is_privileged = TRUE;			
			*out_is_temporary = has_sufficient_privilege_is_temp;
			*out_is_privileged_but_restricted = NULL;
			goto out;
		}
	}

	/* then check temporary privileges as it's OK to have a
	 * privilege temporarily without having the all the
	 * RequiredPrivileges.
	 */

	if ((*out_is_privileged == FALSE) && have_temp_privilege != NULL) {
		gboolean ignore_resource;

		if (recursion_counter == 0)
			ignore_resource = FALSE;
		else
			ignore_resource = TRUE;

		/* TODO: ask for restriction */
		if (have_temp_privilege (uid, policy, resource, ignore_resource, have_temp_privilege_userdata)) {

			res = POLICY_RESULT_OK;
			*out_is_privileged = TRUE;
			*out_is_temporary = TRUE;
			*out_is_privileged_but_restricted = NULL;
			goto out;
		}
	}


	/* now check RequiredPrivileges.. if we have don't have all of those, then return FALSE */

	res = policy_get_required_privileges (policy, &required_privs);
	if (res != POLICY_RESULT_OK)
		goto out;

	for (l = required_privs; l != NULL; l = g_list_next (l)) {
		gboolean has_required_privilege = FALSE;
		gboolean has_required_privilege_is_temp = FALSE;
		char *has_required_privilege_is_restricted = NULL;
		const char *required_privilege = (const char *) l->data;

		g_message ("  checking for required privilege  '%s'", required_privilege);

		has_required_privilege = FALSE;
		res2 = _policy_is_uid_gid_allowed_for_policy (uid, num_gids, gid_list, 
							      required_privilege, NULL, 
							      &has_required_privilege,
							      &has_required_privilege_is_temp,
							      &has_required_privilege_is_restricted,
							      have_temp_privilege_userdata,
							      have_temp_privilege, recursion_counter + 1);
		if (res2 != POLICY_RESULT_OK)
			goto out;

		if (!has_required_privilege || 
		    (has_required_privilege && has_required_privilege_is_restricted != NULL)) {
			g_message ("Returned FALSE because we don't have the required privilege '%s' for privilege '%s'",
				   required_privilege, policy);
			res = POLICY_RESULT_OK;
			*out_is_privileged = FALSE;			
			*out_is_temporary = TRUE;
			*out_is_privileged_but_restricted = NULL;
			goto out;
		}
	}

	/* Check against whitelist and blacklist */

	res = policy_get_whitelist (policy, &whitelist);
	if (res != POLICY_RESULT_OK)
		goto out;

	res = policy_get_blacklist (policy, &blacklist);
	if (res != POLICY_RESULT_OK)
		goto out;

	is_in_whitelist = FALSE;
	is_in_blacklist = FALSE;

	/*  Algorithm: To succeed.. we must be in the whitelist.. and not in the blacklist */

	for (l = whitelist; l != NULL; l = g_list_next (l)) {
		PolicyElement *elem;
		elem = (PolicyElement *) l->data;
		if ((elem->resource == NULL) ||
		    ((resource != NULL) && (strcmp (elem->resource, resource) == 0))) {
			afp_process_elem (elem, &is_in_whitelist, uid, num_gids, gid_list);
		}
	}

	for (l = blacklist; l != NULL; l = g_list_next (l)) {
		PolicyElement *elem;
		elem = (PolicyElement *) l->data;
		if ((elem->resource == NULL) ||
		    ((resource != NULL) && (strcmp (elem->resource, resource) == 0))) {
			afp_process_elem (elem, &is_in_blacklist, uid, num_gids, gid_list);
		}
	}

	*out_is_privileged =  is_in_whitelist && (!is_in_blacklist);
	*out_is_temporary = FALSE;
	*out_is_privileged_but_restricted = NULL;

	res = POLICY_RESULT_OK;

out:
	if (required_privs != NULL) {
		g_list_foreach (required_privs, (GFunc) g_free, NULL);
		g_list_free (required_privs);
	}
	if (sufficient_privs != NULL) {
		g_list_foreach (sufficient_privs, (GFunc) g_free, NULL);
		g_list_free (sufficient_privs);
	}
	if (whitelist != NULL)
		policy_element_free_list (whitelist);
	if (blacklist != NULL)
		policy_element_free_list (blacklist);

	return res;	
}


PolicyResult 
policy_is_uid_gid_allowed_for_policy (uid_t           uid, 
				      guint           num_gids,
				      gid_t          *gid_list,
				      const char     *policy, 
				      const char     *resource,
				      gboolean       *out_is_privileged,
				      gboolean       *out_is_temporary,
				      char          **out_is_privileged_but_restricted,
				      gpointer        have_temp_privilege_userdata,
				      HaveTempPrivCB  have_temp_privilege)
{
	return _policy_is_uid_gid_allowed_for_policy (uid, num_gids, gid_list, policy, 
						      resource, 
						      out_is_privileged, 
						      out_is_temporary, 
						      out_is_privileged_but_restricted, 
						      have_temp_privilege_userdata,
						      have_temp_privilege, 0);
}

char *
policy_util_uid_to_name (uid_t  uid, 
			 gid_t *default_gid)
{
	int rc;
	char *res;
	char *buf = NULL;
	unsigned int bufsize;
	struct passwd pwd;
	struct passwd *pwdp;

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
policy_util_gid_to_name (gid_t gid)
{
	int rc;
	char *res;
	char *buf = NULL;
	unsigned int bufsize;
	struct group gbuf;
	struct group *gbufp;

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
policy_util_name_to_uid (const char *username, gid_t *default_gid)
{
	int rc;
	uid_t res;
	char *buf = NULL;
	unsigned int bufsize;
	struct passwd pwd;
	struct passwd *pwdp;

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
policy_util_name_to_gid (const char *groupname)
{
	int rc;
	gid_t res;
	char *buf = NULL;
	unsigned int bufsize;
	struct group gbuf;
	struct group *gbufp;

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

PolicyResult 
policy_get_allowed_resources_for_policy_for_uid (uid_t                  uid, 
						 const char            *policy, 
						 GList                **result)
{
	int num_groups = 0;
	gid_t *groups = NULL;
	char *username;
	gid_t default_gid;
	PolicyResult  r;

	r = POLICY_RESULT_ERROR;

	if ((username = policy_util_uid_to_name (uid, &default_gid)) == NULL)
		goto out;

	if (getgrouplist(username, default_gid, NULL, &num_groups) < 0) {
		groups = (gid_t *) g_new0 (gid_t, num_groups);
		if (getgrouplist(username, default_gid, groups, &num_groups) < 0) {
			g_warning ("getgrouplist() failed");
			goto out;
		}
	}

	r = policy_get_allowed_resources_for_policy_for_uid_gid (uid,
								 num_groups,
								 groups,
								 policy,
								 result);

out:
	g_free (username);
	g_free (groups);
	return r;
}

PolicyResult 
policy_is_uid_allowed_for_policy (uid_t           uid, 
				  const char     *policy, 
				  const char     *resource,
				  gboolean       *out_is_privileged,
				  gboolean       *out_is_temporary,
				  char          **out_is_privileged_but_restricted,
				  gpointer        have_temp_privilege_userdata,
				  HaveTempPrivCB  have_temp_privilege)
{
	int num_groups = 0;
	gid_t *groups = NULL;
	char *username;
	gid_t default_gid;
	PolicyResult  r;

	r = POLICY_RESULT_ERROR;

	if ((username = policy_util_uid_to_name (uid, &default_gid)) == NULL)
		goto out;

	if (getgrouplist(username, default_gid, NULL, &num_groups) < 0) {
		groups = (gid_t *) g_new0 (gid_t, num_groups);
		if (getgrouplist(username, default_gid, groups, &num_groups) < 0) {
			g_warning ("getgrouplist() failed");
			goto out;
		}
	}

	r = policy_is_uid_gid_allowed_for_policy (uid,
						  num_groups,
						  groups,
						  policy,
						  resource,
						  out_is_privileged, 
						  out_is_temporary, 
						  out_is_privileged_but_restricted, 
						  have_temp_privilege_userdata,
						  have_temp_privilege);

out:
	g_free (username);
	g_free (groups);
	return r;
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

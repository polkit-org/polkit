/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-manager.c : Manager object
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

#include <string.h>
#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "polkit-marshal.h"
#include "polkit-manager.h"
#include "polkit-session.h"

#include "policy.h"

typedef struct
{
	uid_t user;
	char *privilege;
	char *resource;
	char *system_bus_unique_name; /* whether the tmp priv is restricted to e.g. :1.43 */
} TemporaryPrivilege;

struct PolicyKitManagerPrivate
{
	DBusGConnection *connection;
	DBusGProxy *bus_proxy;

	GList *temporary_privileges;

	GHashTable *connection_name_to_caller_info;

	GHashTable *connection_name_to_session_object;
};

G_DEFINE_TYPE(PolicyKitManager, polkit_manager, G_TYPE_OBJECT)

static GObjectClass *parent_class = NULL;



static void
_granting_temp_priv (PolicyKitManager *manager, 
		     TemporaryPrivilege *p)
{
	g_debug ("Granting temporary privilege '%s' to uid %d on resource '%s'",
		 p->privilege, p->user, p->resource != NULL ? p->resource : "(none)");
	/* TODO: send out D-BUS signal */
}

static void
_revoking_temp_priv (PolicyKitManager *manager, 
		     TemporaryPrivilege *p)
{
	g_debug ("Revoking temporary privilege '%s' to uid %d on resource '%s'",
		 p->privilege, p->user, p->resource != NULL ? p->resource : "(none)");
	/* TODO: send out D-BUS signal */
}


typedef struct {
	uid_t  uid;
	pid_t  pid;
} CallerInfo;

static void 
caller_info_delete (gpointer data)
{
	CallerInfo *caller_info = (CallerInfo *) data;
	g_free (caller_info);
}

static void
polkit_manager_init (PolicyKitManager *manager)
{
	manager->priv = g_new0 (PolicyKitManagerPrivate, 1);
	manager->priv->connection = NULL;
	manager->priv->temporary_privileges = NULL;

	manager->priv->connection_name_to_caller_info = g_hash_table_new_full (g_str_hash,
									       g_str_equal,
									       g_free,
									       caller_info_delete);

	manager->priv->connection_name_to_session_object = g_hash_table_new_full (g_str_hash,
										  g_str_equal,
										  g_free,
										  NULL);
}

static void
polkit_manager_finalize (PolicyKitManager *manager)
{
	dbus_g_connection_unref (manager->priv->connection);

	g_hash_table_destroy (manager->priv->connection_name_to_caller_info);

	g_free (manager->priv);

	G_OBJECT_CLASS (parent_class)->finalize (G_OBJECT (manager));
}

static void
polkit_manager_class_init (PolicyKitManagerClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->finalize = (GObjectFinalizeFunc) polkit_manager_finalize;
	parent_class = g_type_class_peek_parent (klass);
}

GQuark
polkit_manager_error_quark (void)
{
	static GQuark ret = 0;
	if (ret == 0)
		ret = g_quark_from_static_string ("PolkitManagerObjectErrorQuark");
	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
polkit_manager_error_get_type (void)
{
	static GType etype = 0;
	
	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (POLKIT_MANAGER_ERROR_NO_SUCH_USER, "NoSuchUser"),
			ENUM_ENTRY (POLKIT_MANAGER_ERROR_NO_SUCH_PRIVILEGE, "NoSuchPrivilege"),
			ENUM_ENTRY (POLKIT_MANAGER_ERROR_NOT_PRIVILEGED, "NotPrivileged"),
			ENUM_ENTRY (POLKIT_MANAGER_ERROR_CANNOT_OBTAIN_PRIVILEGE, "CannotObtainPrivilege"),
			ENUM_ENTRY (POLKIT_MANAGER_ERROR_ERROR, "Error"),
			{ 0, 0, 0 }
		};
		
		g_assert (POLKIT_MANAGER_NUM_ERRORS == G_N_ELEMENTS (values) - 1);
		
		etype = g_enum_register_static ("PolkitManagerError", values);
	}
	
	return etype;
}


static void
bus_name_owner_changed (DBusGProxy  *bus_proxy, 
			const char  *service_name, 
			const char  *old_service_name, 
			const char  *new_service_name, 
			gpointer     user_data)
{
	PolicyKitManager *manager = POLKIT_MANAGER (user_data);

	/* track disconnects of clients */

	if (strlen (new_service_name) == 0) {
		CallerInfo *caller_info;
		PolicyKitSession *session;
		GList *i;
		TemporaryPrivilege *p;

		/* evict CallerInfo from cache */
		caller_info = (CallerInfo *) g_hash_table_lookup (manager->priv->connection_name_to_caller_info, 
								  old_service_name);
		if (caller_info != NULL) {
			g_hash_table_remove (manager->priv->connection_name_to_caller_info, old_service_name);
		}

		/* session object */
		session = POLKIT_SESSION (g_hash_table_lookup (manager->priv->connection_name_to_session_object,
							       old_service_name));
		if (session != NULL) {
			/* possibly revoke temporary privileges granted */
			polkit_session_initiator_disconnected (session);

			/* end the session */
			g_object_unref (session);

			g_hash_table_remove (manager->priv->connection_name_to_session_object, old_service_name);
		}

		/* revoke any temporary privileges that is restricted to this name */
		for (i = manager->priv->temporary_privileges; i != NULL; ) {
			p = (TemporaryPrivilege *) i->data;

			i = g_list_next (i);

			if (p->system_bus_unique_name != NULL && 
			    strcmp (p->system_bus_unique_name, old_service_name) == 0) {

				/* da, revoke this privilege */
				_revoking_temp_priv (manager, p);

				g_free (p->privilege);
				g_free (p->resource);
				g_free (p->system_bus_unique_name);
				g_free (p);

				manager->priv->temporary_privileges = g_list_remove (
					manager->priv->temporary_privileges, p);
			}
		}

	}

	/*g_message ("NameOwnerChanged: service_name='%s', old_service_name='%s' new_service_name='%s'", 
	  service_name, old_service_name, new_service_name);*/
	
}


static gboolean
session_remover (gpointer key,
		 gpointer value,
		 gpointer user_data)
{
	if (value == user_data) {
		return TRUE;
	}
	return FALSE;
}

static void
session_finalized (gpointer  data,
		   GObject  *where_the_object_was)
{
	PolicyKitManager *manager = POLKIT_MANAGER (data);
	
	g_hash_table_foreach_remove (manager->priv->connection_name_to_session_object, 
				     session_remover,
				     where_the_object_was);
}

PolicyKitManager *
polkit_manager_new (DBusGConnection *connection, DBusGProxy *bus_proxy)
{
	PolicyKitManager *manager;

	manager = g_object_new (POLKIT_TYPE_MANAGER, NULL);
	manager->priv->connection = dbus_g_connection_ref (connection);
	dbus_g_connection_register_g_object (manager->priv->connection, 
					     "/org/freedesktop/PolicyKit/Manager", 
					     G_OBJECT (manager));

	manager->priv->bus_proxy = bus_proxy;

	dbus_g_object_register_marshaller (polkit_marshal_VOID__STRING_STRING_STRING, 
					   G_TYPE_NONE, 
					   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_add_signal (bus_proxy, "NameOwnerChanged", G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (bus_proxy, "NameOwnerChanged", G_CALLBACK (bus_name_owner_changed),
				     manager, NULL);

	return manager;
}


static uid_t
uid_from_username (const char *user)
{
	uid_t uid;

	if (g_ascii_isdigit (user[0])) {
		char *endp;
		uid = (uid_t) g_ascii_strtoull (user, &endp, 0);
		if (endp[0] != '\0') {
			uid = (uid_t) -1;
		}
	} else {
		uid = policy_util_name_to_uid (user, NULL);
	}

	return uid;
}

/* remote methods */

static int
safe_strcmp (const char *s1, const char *s2)
{
	if (s1 == NULL || s2 == NULL)
		return 0;
	else
		return strcmp (s1, s2);
}

gboolean
polkit_manager_get_caller_info (PolicyKitManager      *manager,
				const char            *sender,
				uid_t                 *calling_uid, 
				pid_t                 *calling_pid)
{
	gboolean res;
	CallerInfo *caller_info;
	GError *error = NULL;
#if 0
	GArray *calling_selinux_context;
#endif
	res = FALSE;

	if (sender == NULL)
		goto out;

	caller_info = g_hash_table_lookup (manager->priv->connection_name_to_caller_info,
					   sender);
	if (caller_info != NULL) {

		res = TRUE;
		*calling_uid = caller_info->uid;
		*calling_pid = caller_info->pid;
		/*g_message ("uid = %d (cached)", *calling_uid);
		  g_message ("pid = %d (cached)", *calling_pid);*/
		goto out;
	}

	if (!dbus_g_proxy_call (manager->priv->bus_proxy, "GetConnectionUnixUser", &error,
				G_TYPE_STRING, sender,
				G_TYPE_INVALID,
				G_TYPE_UINT, calling_uid,
				G_TYPE_INVALID)) {
		g_warning ("GetConnectionUnixUser() failed: %s", error->message);
		g_error_free (error);
		goto out;
	}

	if (!dbus_g_proxy_call (manager->priv->bus_proxy, "GetConnectionUnixProcessID", &error,
				G_TYPE_STRING, sender,
				G_TYPE_INVALID,
				G_TYPE_UINT, calling_pid,
				G_TYPE_INVALID)) {
		g_warning ("GetConnectionUnixProcessID() failed: %s", error->message);
		g_error_free (error);
		goto out;
	}

#if 0
	if (!dbus_g_proxy_call (manager->priv->bus_proxy, "GetConnectionSELinuxSecurityContext", &error,
				G_TYPE_STRING, sender,
				G_TYPE_INVALID,
				dbus_g_type_get_collection ("GArray", G_TYPE_UCHAR), &calling_selinux_context,
				G_TYPE_INVALID)) {
		g_warning ("GetConnectionSELinuxSecurityContext() failed: %s", error->message);
		g_error_free (error);
		goto out;
	}

	char *selinux_context_string;
	g_array_append_val (calling_selinux_context, "\0");
	selinux_context_string = (char *) g_array_free (calling_selinux_context, FALSE);
	g_message ("selinux context = '%s' for sender '%s'", selinux_context_string, sender);
	g_free (selinux_context_string);
#endif

	caller_info = g_new0 (CallerInfo, 1);
	caller_info->uid = *calling_uid;
	caller_info->pid = *calling_pid;

	g_hash_table_insert (manager->priv->connection_name_to_caller_info,
			     g_strdup (sender), 
			     caller_info);

	res = TRUE;

	/*g_message ("uid = %d", *calling_uid);
	  g_message ("pid = %d", *calling_pid);*/

out:
	return res;
}


typedef struct 
{
	PolicyKitManager      *manager;
	char                  *system_bus_unique_name;
	char                  *privileged_but_restricted_to;
	gboolean               is_temporary;
} TempPrivCheckUserData;

static gboolean
_check_for_temp_privilege (uid_t       user,
			   const char *privilege,
			   const char *resource,
			   gboolean    ignore_resource,
			   gpointer    userdata)
{
	GList *i;
	TempPrivCheckUserData *tpcud = (TempPrivCheckUserData *) userdata;
	gboolean is_privileged;
	
	is_privileged = FALSE;

	g_message ("in _check_for_temp_privilege for user=%d priv=%s resource=%s sbun=%s",
		   user, privilege, resource, tpcud->system_bus_unique_name);

	for (i = tpcud->manager->priv->temporary_privileges; i != NULL; i = g_list_next (i)) {
		TemporaryPrivilege *p;
		gboolean res_match;

		p = (TemporaryPrivilege *) i->data;

		if (ignore_resource) {
			res_match = TRUE;
		} else {
			if (resource == NULL || strlen (resource) == 0)
				res_match = (p->resource == NULL);
			else
				res_match = (safe_strcmp (p->resource, resource) == 0);
		}
		
		if ((strcmp (p->privilege, privilege) == 0) &&
		    res_match &&
		    (p->user == user)) {

			if (p->system_bus_unique_name == NULL) {
				is_privileged = TRUE;
				tpcud->is_temporary = TRUE;
				break;
			} else if (strcmp (p->system_bus_unique_name, tpcud->system_bus_unique_name) == 0) {
				is_privileged = TRUE;
				tpcud->is_temporary = TRUE;
				break;
			} else {
				tpcud->privileged_but_restricted_to = p->system_bus_unique_name;
			}
			
		}
	}

	return is_privileged;
}

gboolean
polkit_manager_initiate_temporary_privilege_grant (PolicyKitManager       *manager, 
						   char                   *user,
						   char                   *privilege,
						   char                   *resource,
						   DBusGMethodInvocation  *context)
{
	uid_t calling_uid;
	pid_t calling_pid;
	uid_t uid;
	PolicyKitSession *session;
	char *sender;

	/* TODO: need to handle limit number of session to prevent DOS.
	 *       Or is dbus-daemon sufficient for that; I think so..
	 */

	if (!polkit_manager_get_caller_info (manager, 
					     dbus_g_method_get_sender (context), 
					     &calling_uid, 
					     &calling_pid)) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	sender = dbus_g_method_get_sender (context);

	uid = uid_from_username (user);

	if (uid == (uid_t) -1) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_USER,
							 "There is no user '%s'.",
							 user));
		return FALSE;
	}

	
	gboolean auth_can_obtain;
	gboolean auth_can_obtain_is_temporary;
	gboolean auth_can_grant;
	gboolean auth_obtain_requires_root;
	PolicyResult res;
	TempPrivCheckUserData tpcud;

	tpcud.manager = manager;
	tpcud.system_bus_unique_name = NULL;
	tpcud.privileged_but_restricted_to = "";
	tpcud.is_temporary = FALSE;

	res = policy_get_auth_details_for_policy (uid,
						  privilege,
						  resource,
						  &auth_can_obtain,
						  &auth_can_obtain_is_temporary,
						  &auth_can_grant,
						  &auth_obtain_requires_root,
						  &tpcud,
						  _check_for_temp_privilege);

	if (!auth_can_obtain) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "The privilege %s cannot be obtained.", privilege));
		return FALSE;
	}

	session = polkit_session_new (manager->priv->connection, 
				      manager,
				      calling_uid,
				      sender,
				      uid,
				      privilege,
				      strlen (resource) > 0 ? resource : NULL,
				      auth_obtain_requires_root);

	g_object_weak_ref (G_OBJECT (session),
			   session_finalized,
			   manager);

	g_hash_table_insert (manager->priv->connection_name_to_session_object,
			     sender,
			     session);

	//g_timeout_add (5 * 1000, destroy_session_after_timeout, session);

	dbus_g_method_return (context,
			      g_strdup (((char *) g_object_get_data (G_OBJECT (session), "dbus_glib_object_path"))));
	return TRUE;
}

gboolean
polkit_manager_is_user_privileged (PolicyKitManager      *manager, 
				   char                  *system_bus_unique_name,
				   char                  *user,
				   char                  *privilege,
				   char                  *resource,
				   DBusGMethodInvocation *context)
{
	uid_t calling_uid;
	pid_t calling_pid;
	uid_t uid;
	PolicyResult res;
	gboolean is_privileged;
	gboolean is_temporary;
	char *is_privileged_but_restricted_to = NULL;
	TempPrivCheckUserData tpcud;

	if (!polkit_manager_get_caller_info (manager, 
					     dbus_g_method_get_sender (context), 
					     &calling_uid, 
					     &calling_pid)) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	is_privileged = FALSE;

	uid = uid_from_username (user);

	if (uid == (uid_t) -1) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_USER,
							 "There is no user '%s'.",
							 user));
		return FALSE;
	}

	/* TODO: check if given uid is privileged to ask for this */
	if (FALSE) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NOT_PRIVILEGED,
							 "You are not authorized to know this."));
		return FALSE;
	}

	tpcud.manager = manager;
	tpcud.system_bus_unique_name = system_bus_unique_name;
	tpcud.privileged_but_restricted_to = "";
	tpcud.is_temporary = FALSE;
	res = policy_is_uid_allowed_for_policy (uid,
						privilege,
						strlen (resource) > 0 ? resource : NULL,
						&is_privileged,
						&is_temporary,
						&is_privileged_but_restricted_to,
						&tpcud,
						_check_for_temp_privilege);
	switch (res) {
	case POLICY_RESULT_OK:
		break;

	case POLICY_RESULT_NO_SUCH_POLICY:
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_PRIVILEGE,
							 "There is no such privilege '%s'.",
							 privilege));
		return FALSE;

	default: /* explicit fallthrough */
	case POLICY_RESULT_ERROR:
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}


	/* if we ended up being privileged, then don't fill in the _but_restricted_to */
	if (is_privileged) {
		g_free (is_privileged_but_restricted_to);
		is_privileged_but_restricted_to = g_strdup ("");
	}

	dbus_g_method_return (context, is_privileged, is_temporary, is_privileged_but_restricted_to);

	g_free (is_privileged_but_restricted_to);

	return TRUE;
}


gboolean
polkit_manager_get_allowed_resources_for_privilege (PolicyKitManager      *manager, 
						    char                  *user,
						    char                  *privilege,
						    DBusGMethodInvocation *context)
{
	uid_t calling_uid;
	pid_t calling_pid;
	int n;
	GList *i;
	GList *resources;
	GList *restrictions;
	uid_t uid;
	PolicyResult res;
	TemporaryPrivilege *p;
	char **resource_list;
	char **restriction_list;
	int num_non_temporary;

	if (!polkit_manager_get_caller_info (manager, 
					     dbus_g_method_get_sender (context), 
					     &calling_uid, 
					     &calling_pid)) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	uid = uid_from_username (user);

	if (uid == (uid_t) -1) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_USER,
							 "There is no user '%s'.",
							 user));
		return FALSE;
	}

	/* TODO: check if given uid is privileged to ask for this */
	if (FALSE) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NOT_PRIVILEGED,
							 "You are not authorized to know this."));
		return FALSE;
	}


	res = policy_get_allowed_resources_for_policy_for_uid (uid,
							       privilege,
							       &resources);
	switch (res) {
	case POLICY_RESULT_OK:
		break;

	case POLICY_RESULT_NO_SUCH_POLICY:
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_PRIVILEGE,
							 "There is no such privilege '%s'.",
							 privilege));
		return FALSE;

	default: /* explicit fallthrough */
	case POLICY_RESULT_ERROR:
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	num_non_temporary = g_list_length (resources);

	restrictions = NULL;

	/* check temporary list */
	for (i = manager->priv->temporary_privileges; i != NULL; i = g_list_next (i)) {
		p = (TemporaryPrivilege *) i->data;

		if ((strcmp (p->privilege, privilege) == 0) &&
		    (p->resource != NULL) &&
		    (p->user == uid)) {

			resources = g_list_append (resources, g_strdup (p->resource));
			restrictions = g_list_append (restrictions, p->system_bus_unique_name != NULL ?
						      p->system_bus_unique_name : "");
		}
	}

	resource_list = g_new0 (char *, g_list_length (resources) + 1);
	for (i = resources, n = 0; i != NULL; i = g_list_next (i)) {
		char *resource = (char *) i->data;
		resource_list[n]  = g_strdup (resource);
		n++;
	}
	resource_list[n] = NULL;

	g_list_foreach (resources, (GFunc) g_free, NULL);
	g_list_free (resources);

	restriction_list = g_new0 (char *, g_list_length (resources) + 1);
	for (n = 0; n < num_non_temporary; n++) {
		restriction_list[n]  = "";
	}
	for (i = restrictions; i != NULL; i = g_list_next (i)) {
		char *restriction = (char *) i->data;
		restriction_list[n]  = g_strdup (restriction);
		n++;
	}
	restriction_list[n] = NULL;

	dbus_g_method_return (context, resource_list, restriction_list, num_non_temporary);

	return TRUE;
}

gboolean
polkit_manager_list_privileges (PolicyKitManager      *manager, 
				DBusGMethodInvocation *context)
{
	uid_t calling_uid;
	pid_t calling_pid;
	int n;
	GList *i;
	GList *privileges;
	PolicyResult res;
	char **privilege_list;


	if (!polkit_manager_get_caller_info (manager, 
					     dbus_g_method_get_sender (context), 
					     &calling_uid, 
					     &calling_pid)) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	/* TODO: check if given uid is privileged to ask for this */
	if (FALSE) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NOT_PRIVILEGED,
							 "You are not authorized to know this."));
		return FALSE;
	}

	res = policy_get_policies (&privileges);
	switch (res) {
	case POLICY_RESULT_OK:
		break;
	
	default: /* explicit fallthrough */
	case POLICY_RESULT_ERROR:
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	privilege_list = g_new0 (char *, g_list_length (privileges) + 1);
	for (i = privileges, n = 0; i != NULL; i = g_list_next (i)) {
		char *privilege = (char *) i->data;
		privilege_list[n++] = g_strdup (privilege);
	}
	privilege_list[n] = NULL;

	g_list_foreach (privileges, (GFunc) g_free, NULL);
	g_list_free (privileges);

	dbus_g_method_return (context, privilege_list);

	return TRUE;
}

gboolean
polkit_manager_revoke_temporary_privilege (PolicyKitManager      *manager, 
					   char                  *user,
					   char                  *privilege,
					   char                  *resource,
					   DBusGMethodInvocation *context)
{
	uid_t uid;
	uid_t calling_uid;
	pid_t calling_pid;
	gboolean result;

	if (!polkit_manager_get_caller_info (manager, 
					     dbus_g_method_get_sender (context), 
					     &calling_uid, 
					     &calling_pid)) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_ERROR,
							 "An error occured."));
		return FALSE;
	}

	uid = uid_from_username (user);

	if (uid == (uid_t) -1) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_USER,
							 "There is no user '%s'.",
							 user));
		return FALSE;
	}

	/* check if given uid is privileged to revoke privilege; only allow own user to do this */
	/* TODO: also allow callers with privilege 'polkit-manage-privileges-TODO-RENAME' */
	if (uid != calling_uid) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NOT_PRIVILEGED,
							 "You are not authorized to revoke the privilege."));
		return FALSE;
	}

	if (resource != NULL && strlen (resource) == 0)
		resource = NULL;

	if (!polkit_manager_remove_temporary_privilege (manager,
							uid,
							privilege,
							resource,
							NULL,
							TRUE)) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_MANAGER_ERROR,
							 POLKIT_MANAGER_ERROR_NO_SUCH_PRIVILEGE,
							 "There is no such privilege '%s'.",
							 privilege));
		return FALSE;
	} 

	result = TRUE;

	dbus_g_method_return (context, result);
	return TRUE;
}

/* local methods */

gboolean
polkit_manager_add_temporary_privilege (PolicyKitManager   *manager, 
					uid_t               user,
					const char         *privilege,
					const char         *resource,
					const char         *system_bus_unique_name)
{
	GList *i;
	TemporaryPrivilege *p;

	for (i = manager->priv->temporary_privileges; i != NULL; i = g_list_next (i)) {
		p = (TemporaryPrivilege *) i->data;

		if ((strcmp (p->privilege, privilege) == 0) &&
		    ((resource != NULL) && (safe_strcmp (p->resource, resource)) == 0) &&
		    (p->user == user) &&
		    (p->system_bus_unique_name == system_bus_unique_name))
			return FALSE;
	}

	p = g_new0 (TemporaryPrivilege, 1);
	p->user = user;
	p->privilege = g_strdup (privilege);
	p->resource = g_strdup (resource);
	p->system_bus_unique_name = g_strdup (system_bus_unique_name);

	_granting_temp_priv (manager, p);
	manager->priv->temporary_privileges = g_list_append (manager->priv->temporary_privileges, p);

	return TRUE;
}

gboolean
polkit_manager_remove_temporary_privilege (PolicyKitManager   *manager, 
					   uid_t               user,
					   const char         *privilege,
					   const char         *resource,
					   const char         *system_bus_unique_name,
					   gboolean            remove_even_if_system_bus_unique_name_does_not_match)
{
	GList *i;
	TemporaryPrivilege *p;

	for (i = manager->priv->temporary_privileges; i != NULL; i = g_list_next (i)) {
		p = (TemporaryPrivilege *) i->data;

		if ((strcmp (p->privilege, privilege) == 0) &&

		    ((resource == NULL) ? (p->resource == NULL) 
		                        : ((p->resource != NULL) ? (strcmp (p->resource, resource) == 0) : FALSE)) &&

		    (p->user == user) &&

		    (remove_even_if_system_bus_unique_name_does_not_match ||
		     ((system_bus_unique_name == NULL) ? (p->system_bus_unique_name == NULL) 
		      : ((p->system_bus_unique_name != NULL) ? 
			 (strcmp (p->system_bus_unique_name, system_bus_unique_name) == 0) : 
			 FALSE)))
			) {

			_revoking_temp_priv (manager, p);

			g_free (p->privilege);
			g_free (p->resource);
			g_free (p->system_bus_unique_name);
			g_free (p);
			
			manager->priv->temporary_privileges = g_list_remove (
				manager->priv->temporary_privileges, p);

			return TRUE;
		}
	}

	return FALSE;
}

void
polkit_manager_update_desktop_console_privileges (PolicyKitManager *manager)
{
	GDir *dir;
	GError *err = NULL;
	const char *f;
	GSList *list;
	GSList *j;
	GList *i;
	TemporaryPrivilege *p;

	g_debug ("Entering polkit_manager_update_desktop_console_privileges");

	/* Build a list of what /var/run/polkit-console contains;
	 * e.g. {":0", "davidz", ":1", "bateman", ..}
	 *
	 * This is essentially a list of pairs <consoleId, userId>
	 * denoting what users are logged in at the consoles attached
	 * to the system.
	 */
	list = NULL;
	if ((dir = g_dir_open (PACKAGE_LOCALSTATEDIR "/run/polkit-console", 0, &err)) == NULL) {
		g_warning ("Unable to open " PACKAGE_LOCALSTATEDIR "/run/polkit-console : %s", err->message);
		g_error_free (err);
		goto out;
	}
	while ((f = g_dir_read_name (dir)) != NULL) {
		char **tokens;

		tokens = g_strsplit (f, "_", 2);
		if (tokens != NULL && g_strv_length (tokens) == 2) {
			char *console;
			char *user;

			console = g_strdup_printf ("console://%s", tokens[0]);
			user = g_strdup (tokens[1]);
			list = g_slist_append (list, console);
			list = g_slist_append (list, user);
		}
		g_strfreev (tokens);
	}
	g_dir_close (dir);

	/* now revoke the temporary desktop-console privilege for
	 * users no longer at the console; go through all tempoary
	 * desktop-console privileges and check that each one is still
	 * in the list above...
	 */
	for (i = manager->priv->temporary_privileges; i != NULL; ) {
		p = (TemporaryPrivilege *) i->data;
		gboolean found;

		i = g_list_next (i);

		found = FALSE;
			
		if ((strcmp (p->privilege, "desktop-console") == 0) && p->resource != NULL) {
			
			for (j = list; j != NULL; j = g_slist_next (j)) {
				char *console;
				char *user;
				uid_t uid;

				console = (char *) j->data;
				j = g_slist_next (j);
				user = (char *) j->data;
				uid = policy_util_name_to_uid (user, NULL);
				if (uid != (uid_t) -1 && strcmp (p->resource, console) == 0 && 
				    p->user == uid && 
				    p->system_bus_unique_name == NULL) {
					found = TRUE;
					break;
				}
			}
		}

		if (!found) {
			/* revoke this privilege */
			_revoking_temp_priv (manager, p);

			g_free (p->privilege);
			g_free (p->resource);
			g_free (p->system_bus_unique_name);
			g_free (p);

			manager->priv->temporary_privileges = g_list_remove (
				manager->priv->temporary_privileges, p);
		} 
	}

	/* finally grant temporary desktop-console privilege for users
	 * now at the console 
	 */
	for (j = list; j != NULL; j = g_slist_next (j)) {
		char *console;
		char *user;
		uid_t uid;
		
		console = (char *) j->data;
		j = g_slist_next (j);
		user = (char *) j->data;
		uid = policy_util_name_to_uid (user, NULL);
		if (uid != (uid_t) -1) {
			polkit_manager_add_temporary_privilege (manager, uid, "desktop-console", console, NULL);
		}
	}

	g_slist_foreach (list, (GFunc) g_free, NULL);
	g_slist_free (list);

out:
	;
}

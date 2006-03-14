/***************************************************************************
 *
 * libpolkit.c : Wraps a subset of methods on the PolicyKit daemon
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
#include <dbus/dbus-glib.h>

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
	DBusConnection *connection;
};

/** Get a new context.
 *
 *  @return                     Pointer to new context or NULL if an error occured
 */
LibPolKitContext *
libpolkit_new_context (DBusConnection *connection)
{
	LibPolKitContext *ctx;

	ctx = g_new0 (LibPolKitContext, 1);
	ctx->magic = LIBPOLKIT_MAGIC;
	ctx->connection = connection;

	return ctx;
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
	g_free (ctx);
	return TRUE;		
}

LibPolKitResult 
libpolkit_get_allowed_resources_for_privilege_for_uid (LibPolKitContext    *ctx,
						       const char          *user, 
						       const char          *privilege, 
						       GList              **result)
{
	LibPolKitResult res;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	char **resource_list;
	int num_resources;
	int i;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	res = LIBPOLKIT_RESULT_ERROR;
	*result = NULL;

	message = dbus_message_new_method_call ("org.freedesktop.PolicyKit",
						"/org/freedesktop/PolicyKit/Manager",
						"org.freedesktop.PolicyKit.Manager",
						"GetAllowedResourcesForPrivilege");
	if (message == NULL) {
		g_warning ("Could not allocate D-BUS message");
		goto out;
	}

	if (!dbus_message_append_args (message, 
				       DBUS_TYPE_STRING, &user, 
				       DBUS_TYPE_STRING, &privilege,
				       DBUS_TYPE_INVALID)) {
		g_warning ("Could not append args to D-BUS message");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection, message, -1, &error);
	if (dbus_error_is_set (&error)) {
		if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.NotPrivileged") == 0) {
			res = LIBPOLKIT_RESULT_NOT_PRIVILEGED;
		} else if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.Error") == 0) {
			res = LIBPOLKIT_RESULT_ERROR;
		}
		dbus_error_free (&error);
		goto out;
	}

	if (!dbus_message_get_args (reply, &error,
				    DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &resource_list, &num_resources,
				    DBUS_TYPE_INVALID)) {
		g_warning ("Could not extract args from D-BUS message: %s : %s", error.name, error.message);
		dbus_error_free (&error);
		goto out;
	}

	for (i = 0; i < num_resources; i++) {
		*result = g_list_append (*result, g_strdup (resource_list[i]));
	}
	dbus_free_string_array (resource_list);

	res = LIBPOLKIT_RESULT_OK;

out:
	if (reply != NULL)
		dbus_message_unref (reply);
	if (message != NULL)
		dbus_message_unref (message);
	return res;
}

LibPolKitResult 
libpolkit_is_uid_allowed_for_privilege (LibPolKitContext    *ctx,
					pid_t                pid,
					const char          *user, 
					const char          *privilege, 
					const char          *resource,
					gboolean            *result)
{
	LibPolKitResult res;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	const char *myresource = "";

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	res = LIBPOLKIT_RESULT_ERROR;
	*result = FALSE;

	message = dbus_message_new_method_call ("org.freedesktop.PolicyKit",
						"/org/freedesktop/PolicyKit/Manager",
						"org.freedesktop.PolicyKit.Manager",
						"IsUserPrivileged");
	if (message == NULL) {
		g_warning ("Could not allocate D-BUS message");
		goto out;
	}

	if (resource != NULL)
		myresource = resource;

	if (!dbus_message_append_args (message, 
				       DBUS_TYPE_INT32, &pid, 
				       DBUS_TYPE_STRING, &user, 
				       DBUS_TYPE_STRING, &privilege,
				       DBUS_TYPE_STRING, &myresource,
				       DBUS_TYPE_INVALID)) {
		g_warning ("Could not append args to D-BUS message");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection, message, -1, &error);
	if (dbus_error_is_set (&error)) {
		if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.NoSuchUser") == 0) {
			res = LIBPOLKIT_RESULT_NO_SUCH_USER;
		} else if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.NoSuchPrivilege") == 0) {
			res = LIBPOLKIT_RESULT_NO_SUCH_PRIVILEGE;
		} else if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.NotPrivileged") == 0) {
			res = LIBPOLKIT_RESULT_NOT_PRIVILEGED;
		} else if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.Error") == 0) {
			res = LIBPOLKIT_RESULT_ERROR;
		}
		dbus_error_free (&error);
		goto out;
	}


	if (!dbus_message_get_args (reply, &error,
				    DBUS_TYPE_BOOLEAN, result,
				    DBUS_TYPE_INVALID)) {
		g_warning ("Could not extract args from D-BUS message: %s : %s", error.name, error.message);
		dbus_error_free (&error);
		goto out;
	}

	res = LIBPOLKIT_RESULT_OK;

out:
	if (reply != NULL)
		dbus_message_unref (reply);
	if (message != NULL)
		dbus_message_unref (message);
	return res;
}

LibPolKitResult
libpolkit_get_privilege_list (LibPolKitContext      *ctx,
			      GList                **result)
{
	LibPolKitResult res;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusError error;
	char **privilege_list;
	int num_privileges;
	int i;

	LIBPOLKIT_CHECK_CONTEXT (ctx, LIBPOLKIT_RESULT_INVALID_CONTEXT);

	res = LIBPOLKIT_RESULT_ERROR;
	*result = NULL;

	message = dbus_message_new_method_call ("org.freedesktop.PolicyKit",
						"/org/freedesktop/PolicyKit/Manager",
						"org.freedesktop.PolicyKit.Manager",
						"ListPrivileges");
	if (message == NULL) {
		g_warning ("Could not allocate D-BUS message");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection, message, -1, &error);
	if (dbus_error_is_set (&error)) {
		if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.NotPrivileged") == 0) {
			res = LIBPOLKIT_RESULT_NOT_PRIVILEGED;
		} else if (strcmp (error.name, "org.freedesktop.PolicyKit.Manager.Error") == 0) {
			res = LIBPOLKIT_RESULT_ERROR;
		}
		dbus_error_free (&error);
		goto out;
	}

	if (!dbus_message_get_args (reply, &error,
				    DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &privilege_list, &num_privileges,
				    DBUS_TYPE_INVALID)) {
		g_warning ("Could not extract args from D-BUS message: %s : %s", error.name, error.message);
		dbus_error_free (&error);
		goto out;
	}

	for (i = 0; i < num_privileges; i++) {
		*result = g_list_append (*result, g_strdup (privilege_list[i]));
	}
	dbus_free_string_array (privilege_list);

	res = LIBPOLKIT_RESULT_OK;

out:
	if (reply != NULL)
		dbus_message_unref (reply);
	if (message != NULL)
		dbus_message_unref (message);
	return res;
}

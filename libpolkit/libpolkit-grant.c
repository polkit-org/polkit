/***************************************************************************
 *
 * libpolkit-grant.c : Wraps temporary grant methods on the PolicyKit daemon
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>

#include <glib/gstdio.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <libpolkit/libpolkit.h>
#include "libpolkit-grant.h"

#include "polkit-interface-manager-glue.h"
#include "polkit-interface-session-glue.h"

struct LibPolKitGrantContext_s
{
	DBusGConnection *dbus_g_connection;
	char *user;
	char *privilege;
	char *resource;
	gboolean restrict_to_dbus_connection;

	LibPolKitGrantQuestions  questions_handler;
	LibPolKitGrantComplete   grant_complete_handler;

	char *auth_user;
	char *auth_service_name;

	DBusGProxy *manager;
	DBusGProxy *session;

	LibPolKitContext *polkit_ctx;

	gpointer    user_data;
};

									       
static void
have_questions_handler (DBusGProxy *session, gpointer user_data)
{
	char **questions;
	GError *error = NULL;
	LibPolKitGrantContext *ctx = (LibPolKitGrantContext *) user_data;
	gboolean should_continue;

	should_continue = FALSE;

	if (!org_freedesktop_PolicyKit_Session_get_questions (ctx->session,
							      &questions,
							      &error)) {
		g_warning ("GetQuestions: %s", error->message);

		/* we're done */
		ctx->grant_complete_handler (ctx, FALSE, error->message, ctx->user_data);

		g_error_free (error);

	} else {
		ctx->questions_handler (ctx, (const char **) questions, ctx->user_data);
		g_strfreev (questions);
	}
}

void
libpolkit_grant_provide_answers (LibPolKitGrantContext *ctx, const char **answers)
{
	GError *error = NULL;

	if (!org_freedesktop_PolicyKit_Session_provide_answers (ctx->session,
								(const char **) answers,
								&error)) {
		g_warning ("ProvideAnswers: %s", error->message);

		/* we're done */
		ctx->grant_complete_handler (ctx, FALSE, error->message, ctx->user_data);

		g_error_free (error);
	}
}


static void
auth_done_handler (DBusGProxy *session, gpointer user_data)
{
	gboolean auth_result;
	//gboolean was_revoked;
	GError *error = NULL;
	LibPolKitGrantContext *ctx = (LibPolKitGrantContext *) user_data;

	/*g_debug ("in %s", __FUNCTION__);*/

	if (!org_freedesktop_PolicyKit_Session_is_authenticated (session,
								 &auth_result,
								 &error)) {
		g_warning ("IsAuthenticated: %s", error->message);

		/* we're done */
		ctx->grant_complete_handler (ctx, FALSE, error->message, ctx->user_data);

		g_error_free (error);
		goto out;
	}

	/*g_message ("Authentication done. %s", auth_result);*/

	if (!auth_result) {
		char *auth_denied_reason;

		if (!org_freedesktop_PolicyKit_Session_get_auth_denied_reason (session,
									       &auth_denied_reason,
									       &error)) {
			g_warning ("GetAuthDeniedReason: %s", error->message);
			g_error_free (error);
			goto out;
		}
		
		/*g_print ("\n"
		  "Authentication failed (reason: '%s').\n", auth_denied_reason);*/

		/* we're done */
		ctx->grant_complete_handler (ctx, FALSE, auth_denied_reason, ctx->user_data);

		g_free (auth_denied_reason);

	} else {
		/*g_print ("\n"
		  "Authentication succeeded.\n");*/

		/* don't restrict privilege to callers unique system bus connection name */
		if (!org_freedesktop_PolicyKit_Session_grant_privilege_temporarily (session,
										    ctx->restrict_to_dbus_connection,
										    &error)) {
			g_warning ("GrantPrivilegeTemporarily: %s", error->message);

			/* we're done */
			ctx->grant_complete_handler (ctx, FALSE, error->message, ctx->user_data);

			g_error_free (error);


		} else {
			/* we're done */
			ctx->grant_complete_handler (ctx, TRUE, NULL, ctx->user_data);

		}

	}


	//sleep (20);

	//libpolkit_revoke_temporary_privilege (ctx, grant_user, grant_privilege, grant_resource, &was_revoked);
	//g_debug ("was revoked = %d", was_revoked);
	//sleep (10000);

out:
	;
}


/**
 * libpolkit_grant_new_context:
 * @user: User to request privilege for
 * @privilege: Privilege to ask for
 * @resource: Resource to ask for. May be NULL.
 * @restrict_to_dbus_connection: Whether the privilege should be restricted to a particular D-BUS connection on the 
 * system message bus.
 * @user_data: User data to be passed to callbacks
 *
 * Create a new context for obtaining a privilege.
 *
 * Returns: The context. It is an opaque data structure. Free with libpolkit_grant_free_context.
 */

LibPolKitGrantContext* 
libpolkit_grant_new_context (DBusGConnection        *dbus_g_connection,
			     const char             *user,
			     const char             *privilege,
			     const char             *resource,
			     gboolean                restrict_to_dbus_connection,
			     gpointer                user_data)
{
	LibPolKitGrantContext* ctx;

	ctx = g_new (LibPolKitGrantContext, 1);
	ctx->dbus_g_connection = dbus_g_connection;
	ctx->user = g_strdup (user);
	ctx->privilege = g_strdup (privilege);
	ctx->resource = g_strdup (resource);
	ctx->restrict_to_dbus_connection = restrict_to_dbus_connection;
	ctx->questions_handler = NULL;
	ctx->grant_complete_handler = NULL;
	ctx->user_data         = user_data;

	ctx->auth_user = NULL;
	ctx->auth_service_name = NULL;

	ctx->polkit_ctx = libpolkit_new_context (dbus_g_connection_get_connection (dbus_g_connection));

	return ctx;
}

LibPolKitContext*
libpolkit_grant_get_libpolkit_context (LibPolKitGrantContext  *ctx)
{
	return ctx->polkit_ctx;
}

void
libpolkit_grant_set_questions_handler (LibPolKitGrantContext   *ctx,
				       LibPolKitGrantQuestions  questions_handler)
{
	ctx->questions_handler = questions_handler;
}

void
libpolkit_grant_set_grant_complete_handler (LibPolKitGrantContext   *ctx,
					    LibPolKitGrantComplete   grant_complete_handler)
{
	ctx->grant_complete_handler = grant_complete_handler;
}

gboolean
libpolkit_grant_initiate_temporary_grant (LibPolKitGrantContext  *ctx)
{
	GError *error = NULL;
	char *session_objpath;
	gboolean rc;

	rc = FALSE;
	if (ctx->questions_handler == NULL ||
	    ctx->grant_complete_handler == NULL)
		goto out;

	ctx->manager = dbus_g_proxy_new_for_name (ctx->dbus_g_connection,
						  "org.freedesktop.PolicyKit",
						  "/org/freedesktop/PolicyKit/Manager",
						  "org.freedesktop.PolicyKit.Manager");
	if (ctx->manager == NULL)
		goto out;

	if (!org_freedesktop_PolicyKit_Manager_initiate_temporary_privilege_grant (ctx->manager,
										   ctx->user,
										   ctx->privilege,
										   ctx->resource,
										   &session_objpath,
										   &error)) {
		g_warning ("GrantPrivilege: %s", error->message);
		g_error_free (error);
		goto out;
	}

	/*g_debug ("session_objpath = %s", session_objpath);*/

	ctx->session = dbus_g_proxy_new_for_name (ctx->dbus_g_connection,
						  "org.freedesktop.PolicyKit",
						  session_objpath,
						  "org.freedesktop.PolicyKit.Session");
	if (ctx->session == NULL)
		goto out;

	dbus_g_proxy_add_signal (ctx->session, "HaveQuestions", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (ctx->session, "HaveQuestions", G_CALLBACK (have_questions_handler),
				     (void *) ctx, NULL);

	dbus_g_proxy_add_signal (ctx->session, "AuthenticationDone", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (ctx->session, "AuthenticationDone", G_CALLBACK (auth_done_handler),
				     (void *) ctx, NULL);

	if (!org_freedesktop_PolicyKit_Session_get_auth_details (ctx->session,
								 &ctx->auth_user,
								 &ctx->auth_service_name,
								 &error)) {
		g_warning ("GetAuthDetails: %s", error->message);
		g_error_free (error);
		goto out;
	}

	if (!org_freedesktop_PolicyKit_Session_initiate_auth (ctx->session,
							      &error)) {
		g_warning ("InitiateAuth: %s", error->message);
		g_error_free (error);
		/* TODO: LIBPOLKIT_GRANT_RESULT_NO_SUCH_PRIVILEGE, LIBPOLKIT_GRANT_RESULT_CANNOT_AUTH_FOR_PRIVILEGE */
		goto out;
	}


	g_free (session_objpath);

	rc = TRUE;
out:

	return rc;
}


const char*
libpolkit_grant_get_user_for_auth (LibPolKitGrantContext  *ctx)
{
	return ctx->auth_user;
}

const char*
libpolkit_grant_get_pam_service_for_auth (LibPolKitGrantContext  *ctx)
{
	return ctx->auth_service_name;
}

gboolean
libpolkit_grant_close (LibPolKitGrantContext  *ctx,
		       gboolean                revoke_privilege)
{
	GError *error = NULL;

	/* got the privilege; now close the session.. */
	if (!org_freedesktop_PolicyKit_Session_close (ctx->session,
						      &error)) {
		g_warning ("Close: %s", error->message);
		g_error_free (error);
	}

	if (revoke_privilege) {
		gboolean was_revoked;

		libpolkit_revoke_temporary_privilege (ctx->polkit_ctx, 
						      ctx->user, 
						      ctx->privilege, 
						      ctx->resource, 
						      &was_revoked);

		if (!was_revoked) {
			g_warning ("Couldn't revoke privilege");
		}

	}

	return TRUE;
}

void
libpolkit_grant_free_context (LibPolKitGrantContext *ctx)
{
	g_free (ctx->user);
	g_free (ctx->privilege);
	g_free (ctx->resource);
	g_free (ctx->auth_user);
	g_free (ctx->auth_service_name);
	libpolkit_free_context (ctx->polkit_ctx);
	g_free (ctx);
}

const char*
libpolkit_grant_get_user (LibPolKitGrantContext *ctx)
{
	return ctx->user;
}

const char* 
libpolkit_grant_get_privilege (LibPolKitGrantContext *ctx)
{
	return ctx->privilege;
}

/**
 * libpolkit_grant_get_resource:
 * @ctx: Context
 *
 * Get the resource as passed in from libpolkit_grant_new_context. 
 *
 * Returns: The resource. May be NULL.
 */
const char* 
libpolkit_grant_get_resource (LibPolKitGrantContext *ctx)
{
	return ctx->resource;
}


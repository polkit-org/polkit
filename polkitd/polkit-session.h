/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-session.h : Session object
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

#ifndef _POLKIT_SESSION_H
#define _POLKIT_SESSION_H

#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include "polkit-manager.h"

GQuark polkit_session_error_quark (void);

#define POLKIT_SESSION_ERROR (polkit_session_error_quark ())

typedef enum
{
        POLKIT_SESSION_ERROR_AUTHENTICATION_IN_PROGRESS = 0,
        POLKIT_SESSION_ERROR_AUTHENTICATION_ALREADY_INITIATED = 1,
	POLKIT_SESSION_ERROR_NO_QUESTIONS = 2,
	POLKIT_SESSION_ERROR_AUTHENTICATION_WAS_NOT_DENIED = 3,
	POLKIT_SESSION_ERROR_NO_RESOURCES = 4,
        POLKIT_SESSION_ERROR_AUTHENTICATION_NOT_DONE = 5,
        POLKIT_SESSION_ERROR_AUTHENTICATION_FAILED = 6,
        POLKIT_SESSION_ERROR_NOT_INITIATOR = 7,
        POLKIT_SESSION_NUM_ERRORS
} PolkitSessionError;

GType polkit_session_error_get_type (void);
#define POLKIT_SESSION_TYPE_ERROR (polkit_session_error_get_type ())

typedef struct PolicyKitSession PolicyKitSession;
typedef struct PolicyKitSessionClass PolicyKitSessionClass;

GType polkit_session_get_type (void);

typedef struct PolicyKitSessionPrivate PolicyKitSessionPrivate;

struct PolicyKitSession
{
	GObject parent;

	PolicyKitSessionPrivate *priv;
};

struct PolicyKitSessionClass
{
	GObjectClass parent;
};

#define POLKIT_TYPE_SESSION              (polkit_session_get_type ())
#define POLKIT_SESSION(object)           (G_TYPE_CHECK_INSTANCE_CAST ((object), POLKIT_TYPE_SESSION, PolicyKitSession))
#define POLKIT_SESSION_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass), POLKIT_TYPE_SESSION, PolicyKitSessionClass))
#define POLKIT_IS_SESSION(object)        (G_TYPE_CHECK_INSTANCE_TYPE ((object), POLKIT_TYPE_SESSION))
#define POLKIT_IS_SESSION_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass), POLKIT_TYPE_SESSION))
#define POLKIT_SESSION_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj), POLKIT_TYPE_SESSION, PolicyKitSessionClass))

PolicyKitSession *polkit_session_new                         (DBusGConnection    *connection, 
							      PolicyKitManager   *manager,
							      uid_t               calling_uid,
							      pid_t               calling_pid,
							      const char         *calling_dbus_name,
							      uid_t               uid,
							      const char         *privilege,
							      const char         *resource);

/* remote methods */

gboolean          polkit_session_is_authenticated            (PolicyKitSession      *session,
							      DBusGMethodInvocation *context);

gboolean          polkit_session_initiate_auth               (PolicyKitSession      *session, 
							      DBusGMethodInvocation *context);

gboolean          polkit_session_get_questions               (PolicyKitSession      *session, 
							      DBusGMethodInvocation *context);

gboolean          polkit_session_provide_answers             (PolicyKitSession      *session, 
							      char                 **answers, 
							      DBusGMethodInvocation *context);

gboolean          polkit_session_close                       (PolicyKitSession      *session, 
							      gboolean               do_not_revoke_privilege,
							      DBusGMethodInvocation *context);

gboolean          polkit_session_get_auth_details            (PolicyKitSession      *session, 
							      DBusGMethodInvocation *context);

gboolean          polkit_session_get_auth_denied_reason      (PolicyKitSession      *session, 
							      DBusGMethodInvocation *context);

gboolean          polkit_session_grant_privilege_temporarily (PolicyKitSession      *session, 
							      gboolean               restrict_to_callers_pid,
							      DBusGMethodInvocation *context);

/* local methods */

void              polkit_session_initiator_disconnected      (PolicyKitSession      *session);


#endif /* _POLKIT_SESSION_H */

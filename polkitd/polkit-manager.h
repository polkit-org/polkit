/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-manager.h : Manager object
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

#ifndef _POLKIT_MANAGER_H
#define _POLKIT_MANAGER_H

#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

GQuark polkit_manager_error_quark (void);

#define POLKIT_MANAGER_ERROR (polkit_manager_error_quark ())

typedef enum
{
        POLKIT_MANAGER_ERROR_NO_SUCH_USER = 0,
	POLKIT_MANAGER_ERROR_NO_SUCH_PRIVILEGE = 1,
	POLKIT_MANAGER_ERROR_NOT_PRIVILEGED = 2,
	POLKIT_MANAGER_ERROR_ERROR = 3,
        POLKIT_MANAGER_NUM_ERRORS
} PolkitManagerError;

GType polkit_manager_error_get_type (void);
#define POLKIT_MANAGER_TYPE_ERROR (polkit_manager_error_get_type ())

typedef struct PolicyKitManager PolicyKitManager;
typedef struct PolicyKitManagerClass PolicyKitManagerClass;

GType polkit_manager_get_type (void);

typedef struct PolicyKitManagerPrivate PolicyKitManagerPrivate;

struct PolicyKitManager
{
	GObject parent;

	PolicyKitManagerPrivate *priv;
};

struct PolicyKitManagerClass
{
	GObjectClass parent;
};

#define POLKIT_TYPE_MANAGER              (polkit_manager_get_type ())
#define POLKIT_MANAGER(object)           (G_TYPE_CHECK_INSTANCE_CAST ((object), POLKIT_TYPE_MANAGER, PolicyKitManager))
#define POLKIT_MANAGER_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass), POLKIT_TYPE_MANAGER, PolicyKitManagerClass))
#define POLKIT_IS_MANAGER(object)        (G_TYPE_CHECK_INSTANCE_TYPE ((object), POLKIT_TYPE_MANAGER))
#define POLKIT_IS_MANAGER_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass), POLKIT_TYPE_MANAGER))
#define POLKIT_MANAGER_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj), POLKIT_TYPE_MANAGER, PolicyKitManagerClass))

PolicyKitManager *polkit_manager_new                                 (DBusGConnection       *connection,
								      DBusGProxy            *bus_proxy);

/* remote methods */

gboolean          polkit_manager_initiate_privilege_grant            (PolicyKitManager      *manager, 
						                      char                  *user,
						                      char                  *privilege,
						                      char                  *resource,
								      DBusGMethodInvocation *context);

gboolean          polkit_manager_is_user_privileged                  (PolicyKitManager      *manager, 
								      int                    pid,
						                      char                  *user,
						                      char                  *privilege,
						                      char                  *resource,
								      DBusGMethodInvocation *context);

gboolean          polkit_manager_get_allowed_resources_for_privilege (PolicyKitManager      *manager, 
								      char                  *user,
								      char                  *privilege,
								      DBusGMethodInvocation *context);

gboolean          polkit_manager_list_privileges                     (PolicyKitManager      *manager, 
								      DBusGMethodInvocation *context);

/* local methods */

gboolean          polkit_manager_get_caller_info                     (PolicyKitManager      *manager,
								      const char            *sender,
								      uid_t                 *calling_uid, 
								      pid_t                 *calling_pid);


gboolean          polkit_manager_add_temporary_privilege             (PolicyKitManager      *manager, 
								      uid_t                  user,
								      const char            *privilege,
								      const char            *resource,
								      pid_t                  pid_restriction);

gboolean          polkit_manager_remove_temporary_privilege          (PolicyKitManager      *manager, 
								      uid_t                  user,
								      const char            *privilege,
								      const char            *resource,
								      pid_t                  pid_restriction);

#endif /* _POLKIT_MANAGER_H */

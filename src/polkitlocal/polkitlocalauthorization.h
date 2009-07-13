/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#if !defined (_POLKIT_LOCAL_COMPILATION) && !defined(_POLKIT_LOCAL_INSIDE_POLKIT_LOCAL_H)
#error "Only <polkitlocal/polkitlocal.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_LOCAL_AUTHORIZATION_H
#define __POLKIT_LOCAL_AUTHORIZATION_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkitlocal/polkitlocaltypes.h>

#if defined (POLKIT_I_KNOW_AUTHORITY_MANAGER_API_IS_SUBJECT_TO_CHANGE) || defined (_POLKIT_COMPILATION)

G_BEGIN_DECLS

#define POLKIT_TYPE_LOCAL_AUTHORIZATION          (polkit_local_authorization_get_type())
#define POLKIT_LOCAL_AUTHORIZATION(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_LOCAL_AUTHORIZATION, PolkitLocalAuthorization))
#define POLKIT_LOCAL_AUTHORIZATION_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_LOCAL_AUTHORIZATION, PolkitLocalAuthorizationClass))
#define POLKIT_LOCAL_AUTHORIZATION_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_LOCAL_AUTHORIZATION, PolkitLocalAuthorizationClass))
#define POLKIT_IS_LOCAL_AUTHORIZATION(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_LOCAL_AUTHORIZATION))
#define POLKIT_IS_LOCAL_AUTHORIZATION_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_LOCAL_AUTHORIZATION))

#if 0
typedef struct _PolkitLocalAuthorization PolkitLocalAuthorization;
#endif
typedef struct _PolkitLocalAuthorizationClass PolkitLocalAuthorizationClass;

GType                polkit_local_authorization_get_type         (void) G_GNUC_CONST;

PolkitLocalAuthorization *polkit_local_authorization_new              (const gchar         *action_id,
                                                            PolkitSubject       *subject,
                                                            gboolean             is_negative);

const gchar         *polkit_local_authorization_get_action_id    (PolkitLocalAuthorization *local_authorization);

PolkitSubject       *polkit_local_authorization_get_subject      (PolkitLocalAuthorization *local_authorization);

gboolean             polkit_local_authorization_get_is_negative  (PolkitLocalAuthorization *local_authorization);

G_END_DECLS

#endif /* API hiding */

#endif /* __POLKIT_LOCAL_AUTHORIZATION_H */

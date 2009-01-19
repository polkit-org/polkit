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

#ifndef __POLKIT_AUTHORIZATION_H
#define __POLKIT_AUTHORIZATION_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkit/polkittypes.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_AUTHORIZATION          (polkit_authorization_get_type())
#define POLKIT_AUTHORIZATION(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORIZATION, PolkitAuthorization))
#define POLKIT_AUTHORIZATION_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_AUTHORIZATION, PolkitAuthorizationClass))
#define POLKIT_AUTHORIZATION_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_AUTHORIZATION, PolkitAuthorizationClass))
#define POLKIT_IS_AUTHORIZATION(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHORIZATION))
#define POLKIT_IS_AUTHORIZATION_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_AUTHORIZATION))

#if 0
typedef struct _PolkitAuthorization PolkitAuthorization;
#endif
typedef struct _PolkitAuthorizationClass PolkitAuthorizationClass;

GType                polkit_authorization_get_type         (void) G_GNUC_CONST;

PolkitAuthorization *polkit_authorization_new              (const gchar         *action_id,
                                                            PolkitSubject       *subject,
                                                            gboolean             is_negative);

const gchar         *polkit_authorization_get_action_id    (PolkitAuthorization *authorization);

PolkitSubject       *polkit_authorization_get_subject      (PolkitAuthorization *authorization);

gboolean             polkit_authorization_get_is_negative  (PolkitAuthorization *authorization);

G_END_DECLS

#endif /* __POLKIT_AUTHORIZATION_H */

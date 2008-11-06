/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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

#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_USER_H__
#define __POLKIT_USER_H__

#include <glib-object.h>
#include <polkit/polkitsubject.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_USER         (polkit_user_get_type ())
#define POLKIT_USER(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_USER, PolkitUser))
#define POLKIT_USER_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_USER, PolkitUserClass))
#define POLKIT_IS_USER(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_USER))
#define POLKIT_IS_USER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_USER))
#define POLKIT_USER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_USER, PolkitUserClass))

typedef struct _PolkitUser        PolkitUser;
typedef struct _PolkitUserClass   PolkitUserClass;
typedef struct _PolkitUserPrivate PolkitUserPrivate;

struct _PolkitUser
{
        GObject             parent_instance;
        PolkitUserPrivate  *priv;
};

struct _PolkitUserClass
{
        GObjectClass parent_class;
};

GType          polkit_user_get_type       (void) G_GNUC_CONST;
PolkitSubject *polkit_user_new            (const char   *user_name);
gchar         *polkit_user_get_user_name  (PolkitUser   *user);
void           polkit_user_set_user_name  (PolkitUser  *user,
                                           const gchar  *user_name);

G_END_DECLS

#endif /* __POLKIT_USER_H__ */

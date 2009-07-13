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

#ifndef __POLKIT_LOCAL_AUTHORITY_H
#define __POLKIT_LOCAL_AUTHORITY_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkitlocal/polkitlocaltypes.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_LOCAL_AUTHORITY          (polkit_local_authority_get_type())
#define POLKIT_LOCAL_AUTHORITY(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_LOCAL_AUTHORITY, PolkitLocalAuthority))
#define POLKIT_LOCAL_AUTHORITY_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_LOCAL_AUTHORITY, PolkitLocalAuthorityClass))
#define POLKIT_LOCAL_AUTHORITY_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_LOCAL_AUTHORITY, PolkitLocalAuthorityClass))
#define POLKIT_IS_LOCAL_AUTHORITY(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_LOCAL_AUTHORITY))
#define POLKIT_IS_LOCAL_AUTHORITY_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_LOCAL_AUTHORITY))

#if 0
typedef struct _PolkitLocalAuthority PolkitLocalAuthority;
#endif
typedef struct _PolkitLocalAuthorityClass PolkitLocalAuthorityClass;

GType         polkit_local_authority_get_type         (void) G_GNUC_CONST;

PolkitLocalAuthority *polkit_local_authority_get (void);

/* ---------------------------------------------------------------------------------------------------- */

GList  *polkit_local_authority_enumerate_users_sync (PolkitLocalAuthority *local_authority,
                                                                          GCancellable    *cancellable,
                                                                          GError         **error);

GList  *polkit_local_authority_enumerate_groups_sync (PolkitLocalAuthority *local_authority,
                                                        GCancellable           *cancellable,
                                                        GError               **error);

GList  *polkit_local_authority_enumerate_authorizations_sync (PolkitLocalAuthority  *local_authority,
                                                                PolkitIdentity          *identity,
                                                                GCancellable            *cancellable,
                                                                GError                 **error);

gboolean  polkit_local_authority_add_authorization_sync (PolkitLocalAuthority     *local_authority,
                                                           PolkitIdentity      *identity,
                                                           PolkitLocalAuthorization *authorization,
                                                           GCancellable        *cancellable,
                                                           GError             **error);

gboolean  polkit_local_authority_remove_authorization_sync (PolkitLocalAuthority     *local_authority,
                                                              PolkitIdentity      *identity,
                                                              PolkitLocalAuthorization *authorization,
                                                              GCancellable        *cancellable,
                                                              GError             **error);

/* ---------------------------------------------------------------------------------------------------- */


void                       polkit_local_authority_enumerate_users (PolkitLocalAuthority     *local_authority,
                                                             GCancellable        *cancellable,
                                                             GAsyncReadyCallback  callback,
                                                             gpointer             user_data);

GList *                    polkit_local_authority_enumerate_users_finish (PolkitLocalAuthority *local_authority,
                                                                    GAsyncResult    *res,
                                                                    GError         **error);

void                       polkit_local_authority_enumerate_groups (PolkitLocalAuthority     *local_authority,
                                                              GCancellable        *cancellable,
                                                              GAsyncReadyCallback  callback,
                                                              gpointer             user_data);

GList *                    polkit_local_authority_enumerate_groups_finish (PolkitLocalAuthority *local_authority,
                                                                     GAsyncResult    *res,
                                                                     GError         **error);

void                       polkit_local_authority_enumerate_authorizations (PolkitLocalAuthority     *local_authority,
                                                                      PolkitIdentity      *identity,
                                                                      GCancellable        *cancellable,
                                                                      GAsyncReadyCallback  callback,
                                                                      gpointer             user_data);

GList *                    polkit_local_authority_enumerate_authorizations_finish (PolkitLocalAuthority *local_authority,
                                                                             GAsyncResult    *res,
                                                                             GError         **error);

void                       polkit_local_authority_add_authorization (PolkitLocalAuthority     *local_authority,
                                                               PolkitIdentity      *identity,
                                                               PolkitLocalAuthorization *authorization,
                                                               GCancellable        *cancellable,
                                                               GAsyncReadyCallback  callback,
                                                               gpointer             user_data);

gboolean                   polkit_local_authority_add_authorization_finish (PolkitLocalAuthority *local_authority,
                                                                      GAsyncResult    *res,
                                                                      GError         **error);

void                       polkit_local_authority_remove_authorization (PolkitLocalAuthority     *local_authority,
                                                                  PolkitIdentity      *identity,
                                                                  PolkitLocalAuthorization *authorization,
                                                                  GCancellable        *cancellable,
                                                                  GAsyncReadyCallback  callback,
                                                                  gpointer             user_data);

gboolean                   polkit_local_authority_remove_authorization_finish (PolkitLocalAuthority *local_authority,
                                                                         GAsyncResult    *res,
                                                                         GError         **error);

/* ---------------------------------------------------------------------------------------------------- */

G_END_DECLS

#endif /* __POLKIT_LOCAL_AUTHORITY_H */

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

#ifndef __POLKIT_AUTHORITY_MANAGER_H
#define __POLKIT_AUTHORITY_MANAGER_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkit/polkittypes.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_AUTHORITY_MANAGER          (polkit_authority_manager_get_type())
#define POLKIT_AUTHORITY_MANAGER(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORITY_MANAGER, PolkitAuthorityManager))
#define POLKIT_AUTHORITY_MANAGER_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_AUTHORITY_MANAGER, PolkitAuthorityManagerClass))
#define POLKIT_AUTHORITY_MANAGER_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_AUTHORITY_MANAGER, PolkitAuthorityManagerClass))
#define POLKIT_IS_AUTHORITY_MANAGER(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHORITY_MANAGER))
#define POLKIT_IS_AUTHORITY_MANAGER_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_AUTHORITY_MANAGER))

#if 0
typedef struct _PolkitAuthorityManager PolkitAuthorityManager;
#endif
typedef struct _PolkitAuthorityManagerClass PolkitAuthorityManagerClass;

GType         polkit_authority_manager_get_type         (void) G_GNUC_CONST;

PolkitAuthorityManager *polkit_authority_manager_get (void);

/* ---------------------------------------------------------------------------------------------------- */

GList  *polkit_authority_manager_enumerate_users_sync (PolkitAuthorityManager *authority_manager,
                                                                          GCancellable    *cancellable,
                                                                          GError         **error);

GList  *polkit_authority_manager_enumerate_groups_sync (PolkitAuthorityManager *authority_manager,
                                                        GCancellable           *cancellable,
                                                        GError               **error);

GList  *polkit_authority_manager_enumerate_authorizations_sync (PolkitAuthorityManager  *authority_manager,
                                                                PolkitIdentity          *identity,
                                                                GCancellable            *cancellable,
                                                                GError                 **error);

gboolean  polkit_authority_manager_add_authorization_sync (PolkitAuthorityManager     *authority_manager,
                                                           PolkitIdentity      *identity,
                                                           PolkitAuthorization *authorization,
                                                           GCancellable        *cancellable,
                                                           GError             **error);

gboolean  polkit_authority_manager_remove_authorization_sync (PolkitAuthorityManager     *authority_manager,
                                                              PolkitIdentity      *identity,
                                                              PolkitAuthorization *authorization,
                                                              GCancellable        *cancellable,
                                                              GError             **error);

/* ---------------------------------------------------------------------------------------------------- */


void                       polkit_authority_manager_enumerate_users (PolkitAuthorityManager     *authority_manager,
                                                             GCancellable        *cancellable,
                                                             GAsyncReadyCallback  callback,
                                                             gpointer             user_data);

GList *                    polkit_authority_manager_enumerate_users_finish (PolkitAuthorityManager *authority_manager,
                                                                    GAsyncResult    *res,
                                                                    GError         **error);

void                       polkit_authority_manager_enumerate_groups (PolkitAuthorityManager     *authority_manager,
                                                              GCancellable        *cancellable,
                                                              GAsyncReadyCallback  callback,
                                                              gpointer             user_data);

GList *                    polkit_authority_manager_enumerate_groups_finish (PolkitAuthorityManager *authority_manager,
                                                                     GAsyncResult    *res,
                                                                     GError         **error);

void                       polkit_authority_manager_enumerate_authorizations (PolkitAuthorityManager     *authority_manager,
                                                                      PolkitIdentity      *identity,
                                                                      GCancellable        *cancellable,
                                                                      GAsyncReadyCallback  callback,
                                                                      gpointer             user_data);

GList *                    polkit_authority_manager_enumerate_authorizations_finish (PolkitAuthorityManager *authority_manager,
                                                                             GAsyncResult    *res,
                                                                             GError         **error);

void                       polkit_authority_manager_add_authorization (PolkitAuthorityManager     *authority_manager,
                                                               PolkitIdentity      *identity,
                                                               PolkitAuthorization *authorization,
                                                               GCancellable        *cancellable,
                                                               GAsyncReadyCallback  callback,
                                                               gpointer             user_data);

gboolean                   polkit_authority_manager_add_authorization_finish (PolkitAuthorityManager *authority_manager,
                                                                      GAsyncResult    *res,
                                                                      GError         **error);

void                       polkit_authority_manager_remove_authorization (PolkitAuthorityManager     *authority_manager,
                                                                  PolkitIdentity      *identity,
                                                                  PolkitAuthorization *authorization,
                                                                  GCancellable        *cancellable,
                                                                  GAsyncReadyCallback  callback,
                                                                  gpointer             user_data);

gboolean                   polkit_authority_manager_remove_authorization_finish (PolkitAuthorityManager *authority_manager,
                                                                         GAsyncResult    *res,
                                                                         GError         **error);

/* ---------------------------------------------------------------------------------------------------- */

G_END_DECLS

#endif /* __POLKIT_AUTHORITY_MANAGER_H */

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

#ifndef __POLKIT_AUTHORITY_H
#define __POLKIT_AUTHORITY_H

#include <glib-object.h>
#include <gio/gio.h>
#include <polkit/polkittypes.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_AUTHORITY          (polkit_authority_get_type())
#define POLKIT_AUTHORITY(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORITY, PolkitAuthority))
#define POLKIT_AUTHORITY_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_AUTHORITY, PolkitAuthorityClass))
#define POLKIT_AUTHORITY_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_AUTHORITY, PolkitAuthorityClass))
#define POLKIT_IS_AUTHORITY(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHORITY))
#define POLKIT_IS_AUTHORITY_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_AUTHORITY))

#if 0
typedef struct _PolkitAuthority PolkitAuthority;
#endif
typedef struct _PolkitAuthorityClass PolkitAuthorityClass;

GType         polkit_authority_get_type         (void) G_GNUC_CONST;

PolkitAuthority *polkit_authority_get (void);

/* ---------------------------------------------------------------------------------------------------- */

GList                     *polkit_authority_enumerate_actions_sync (PolkitAuthority *authority,
                                                                    const gchar     *locale,
                                                                    GCancellable    *cancellable,
                                                                    GError         **error);

GList                     *polkit_authority_enumerate_users_sync (PolkitAuthority *authority,
                                                                  GCancellable    *cancellable,
                                                                  GError         **error);

GList                     *polkit_authority_enumerate_groups_sync (PolkitAuthority *authority,
                                                                   GCancellable    *cancellable,
                                                                   GError         **error);

PolkitAuthorizationResult  polkit_authority_check_authorization_sync (PolkitAuthority               *authority,
                                                                      PolkitSubject                 *subject,
                                                                      const gchar                   *action_id,
                                                                      PolkitCheckAuthorizationFlags  flags,
                                                                      GCancellable                  *cancellable,
                                                                      GError                       **error);

GList                     *polkit_authority_enumerate_authorizations_sync (PolkitAuthority  *authority,
                                                                           PolkitIdentity   *identity,
                                                                           GCancellable     *cancellable,
                                                                           GError          **error);

gboolean                   polkit_authority_add_authorization_sync (PolkitAuthority     *authority,
                                                                    PolkitIdentity      *identity,
                                                                    PolkitAuthorization *authorization,
                                                                    GCancellable        *cancellable,
                                                                    GError             **error);

gboolean                   polkit_authority_remove_authorization_sync (PolkitAuthority     *authority,
                                                                       PolkitIdentity      *identity,
                                                                       PolkitAuthorization *authorization,
                                                                       GCancellable        *cancellable,
                                                                       GError             **error);

/* ---------------------------------------------------------------------------------------------------- */

void                       polkit_authority_enumerate_actions (PolkitAuthority     *authority,
                                                               const gchar         *locale,
                                                               GCancellable        *cancellable,
                                                               GAsyncReadyCallback  callback,
                                                               gpointer             user_data);

GList *                    polkit_authority_enumerate_actions_finish (PolkitAuthority *authority,
                                                                      GAsyncResult    *res,
                                                                      GError         **error);

void                       polkit_authority_enumerate_users (PolkitAuthority     *authority,
                                                             GCancellable        *cancellable,
                                                             GAsyncReadyCallback  callback,
                                                             gpointer             user_data);

GList *                    polkit_authority_enumerate_users_finish (PolkitAuthority *authority,
                                                                    GAsyncResult    *res,
                                                                    GError         **error);

void                       polkit_authority_enumerate_groups (PolkitAuthority     *authority,
                                                              GCancellable        *cancellable,
                                                              GAsyncReadyCallback  callback,
                                                              gpointer             user_data);

GList *                    polkit_authority_enumerate_groups_finish (PolkitAuthority *authority,
                                                                     GAsyncResult    *res,
                                                                     GError         **error);

void                       polkit_authority_check_authorization (PolkitAuthority               *authority,
                                                                 PolkitSubject                 *subject,
                                                                 const gchar                   *action_id,
                                                                 PolkitCheckAuthorizationFlags  flags,
                                                                 GCancellable                  *cancellable,
                                                                 GAsyncReadyCallback            callback,
                                                                 gpointer                       user_data);

PolkitAuthorizationResult  polkit_authority_check_authorization_finish (PolkitAuthority          *authority,
                                                                        GAsyncResult             *res,
                                                                        GError                  **error);

void                       polkit_authority_enumerate_authorizations (PolkitAuthority     *authority,
                                                                      PolkitIdentity      *identity,
                                                                      GCancellable        *cancellable,
                                                                      GAsyncReadyCallback  callback,
                                                                      gpointer             user_data);

GList *                    polkit_authority_enumerate_authorizations_finish (PolkitAuthority *authority,
                                                                             GAsyncResult    *res,
                                                                             GError         **error);

void                       polkit_authority_add_authorization (PolkitAuthority     *authority,
                                                               PolkitIdentity      *identity,
                                                               PolkitAuthorization *authorization,
                                                               GCancellable        *cancellable,
                                                               GAsyncReadyCallback  callback,
                                                               gpointer             user_data);

gboolean                   polkit_authority_add_authorization_finish (PolkitAuthority *authority,
                                                                      GAsyncResult    *res,
                                                                      GError         **error);

void                       polkit_authority_remove_authorization (PolkitAuthority     *authority,
                                                                  PolkitIdentity      *identity,
                                                                  PolkitAuthorization *authorization,
                                                                  GCancellable        *cancellable,
                                                                  GAsyncReadyCallback  callback,
                                                                  gpointer             user_data);

gboolean                   polkit_authority_remove_authorization_finish (PolkitAuthority *authority,
                                                                         GAsyncResult    *res,
                                                                         GError         **error);


/* ---------------------------------------------------------------------------------------------------- */

G_END_DECLS

#endif /* __POLKIT_AUTHORITY_H */

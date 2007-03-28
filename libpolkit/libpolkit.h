/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit.h : library for querying system-wide policy
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
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

#ifndef LIBPOLKIT_H
#define LIBPOLKIT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

struct PolKitContext_s;
typedef struct PolKitContext_s PolKitContext;

/**
 * PolKitContextConfigChangedCB:
 * @pk_context: PolicyKit context
 * @resources_associated_with_seat: A NULL terminated array of resources associated with the seat
 * @user_data: user data
 *
 * Called when configuration changes. Mechanisms should listen on this
 * signal and e.g. reconfigure all permissions / acl's they have set
 * in response to policy decisions made from information provided by
 * PolicyKit.
 */
typedef void (*PolKitContextConfigChangedCB) (PolKitContext  *pk_context,
                                              gpointer        user_data);

PolKitContext *libpolkit_context_new                (void);
PolKitContext *libpolkit_context_ref                (PolKitContext                *pk_context);
void           libpolkit_context_set_config_changed (PolKitContext                *pk_context, 
                                                     PolKitContextConfigChangedCB  cb, 
                                                     gpointer                      user_data);
void           libpolkit_context_unref              (PolKitContext                *pk_context);


struct PolKitPrivilege_s;
typedef struct PolKitPrivilege_s PolKitPrivilege;

PolKitPrivilege *libpolkit_privilege_new              (void);
PolKitPrivilege *libpolkit_privilege_ref              (PolKitPrivilege *privilege);
void             libpolkit_privilege_set_privilege_id (PolKitPrivilege *privilege, const char  *privilege_id);
gboolean         libpolkit_privilege_get_privilege_id (PolKitPrivilege *privilege, char       **out_privilege_id);
void             libpolkit_privilege_unref            (PolKitPrivilege *privilege);

struct PolKitResource_s;
typedef struct PolKitResource_s PolKitResource;

PolKitResource *libpolkit_resource_new               (void);
PolKitResource *libpolkit_resource_ref               (PolKitResource *resource);
void            libpolkit_resource_set_resource_type (PolKitResource *resource, const char  *resource_type);
void            libpolkit_resource_set_resource_id   (PolKitResource *resource, const char  *resource_id);
gboolean        libpolkit_resource_get_resource_type (PolKitResource *resource, char       **out_resource_type);
gboolean        libpolkit_resource_get_resource_id   (PolKitResource *resource, char       **out_resource_id);
void            libpolkit_resource_unref             (PolKitResource *resource);


struct PolKitSeat_s;
typedef struct PolKitSeat_s PolKitSeat;

PolKitSeat     *libpolkit_seat_new             (void);
PolKitSeat     *libpolkit_seat_ref             (PolKitSeat *seat);
void            libpolkit_seat_set_ck_objref   (PolKitSeat *seat, const char *ck_objref);
gboolean        libpolkit_seat_get_ck_objref   (PolKitSeat *seat, char **out_ck_objref);
void            libpolkit_seat_unref           (PolKitSeat *seat);


struct PolKitSession_s;
typedef struct PolKitSession_s PolKitSession;

PolKitSession     *libpolkit_session_new                (void);
PolKitSession     *libpolkit_session_ref                (PolKitSession *session);
void               libpolkit_session_set_uid            (PolKitSession *session, uid_t       uid);
void               libpolkit_session_set_ck_objref      (PolKitSession *session, const char *ck_objref);
void               libpolkit_session_set_ck_is_active   (PolKitSession *session, gboolean    is_active);
void               libpolkit_session_set_ck_is_local    (PolKitSession *session, gboolean    is_local);
void               libpolkit_session_set_ck_remote_host (PolKitSession *session, const char *remote_host);
void               libpolkit_session_set_ck_seat        (PolKitSession *session, PolKitSeat     *seat);
gboolean           libpolkit_session_get_uid            (PolKitSession *session, uid_t      *out_uid);
gboolean           libpolkit_session_get_ck_objref      (PolKitSession *session, char      **out_ck_objref);
gboolean           libpolkit_session_get_ck_is_active   (PolKitSession *session, gboolean   *out_is_active);
gboolean           libpolkit_session_get_ck_is_local    (PolKitSession *session, gboolean   *out_is_local);
gboolean           libpolkit_session_get_ck_remote_host (PolKitSession *session, char       *out_remote_host);
gboolean           libpolkit_session_get_ck_seat        (PolKitSession *session, PolKitSeat    **out_seat);
void               libpolkit_session_unref              (PolKitSession *session);


struct PolKitCaller_s;
typedef struct PolKitCaller_s PolKitCaller;

PolKitCaller     *libpolkit_caller_new                 (void);
PolKitCaller     *libpolkit_caller_ref                 (PolKitCaller *caller);
void              libpolkit_caller_set_dbus_name       (PolKitCaller *caller, const char *dbus_name);
void              libpolkit_caller_set_uid             (PolKitCaller *caller, uid_t       uid);
void              libpolkit_caller_set_pid             (PolKitCaller *caller, pid_t       pid);
void              libpolkit_caller_set_selinux_context (PolKitCaller *caller, const char *selinux_context);
void              libpolkit_caller_set_ck_session      (PolKitCaller *caller, PolKitSession  *session);
gboolean          libpolkit_caller_get_dbus_name       (PolKitCaller *caller, char      **out_dbus_name);
gboolean          libpolkit_caller_get_uid             (PolKitCaller *caller, uid_t      *out_uid);
gboolean          libpolkit_caller_get_pid             (PolKitCaller *caller, uid_t      *out_pid);
gboolean          libpolkit_caller_get_selinux_context (PolKitCaller *caller, char       *out_selinux_context);
gboolean          libpolkit_caller_get_ck_session      (PolKitCaller *caller, PolKitSession **out_session);
void              libpolkit_caller_unref               (PolKitCaller *caller);

/**
 * PolKitSeatVisitorCB:
 * @seat: the seat
 * @resources_associated_with_seat: A NULL terminated array of resources associated with the seat
 * @user_data: user data
 *
 * Visitor function for libpolkit_get_seat_resource_association(). The caller should _not_ unref the passed objects.
 *
 */
typedef void (*PolKitSeatVisitorCB) (PolKitSeat      *seat,
                                     PolKitResource **resources_associated_with_seat,
                                     gpointer         user_data);

void
libpolkit_get_seat_resource_association (PolKitContext       *pk_context,
                                         PolKitSeatVisitorCB  visitor,
                                         gpointer            *user_data);

gboolean
libpolkit_is_resource_associated_with_seat (PolKitContext   *pk_context,
                                            PolKitResource  *resource,
                                            PolKitSeat      *seat);

gboolean
libpolkit_can_session_access_resource (PolKitContext   *pk_context,
                                       PolKitPrivilege *privilege,
                                       PolKitResource  *resource,
                                       PolKitSession   *session);

gboolean
libpolkit_can_caller_access_resource (PolKitContext   *pk_context,
                                      PolKitPrivilege *privilege,
                                      PolKitResource  *resource,
                                      PolKitCaller    *caller);

#endif /* LIBPOLKIT_H */



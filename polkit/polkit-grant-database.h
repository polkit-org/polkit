/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant-database.h : simple interface for storing and checking grants
 * 
 * (This is an internal and private interface to PolicyKit. Do not use.)
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifndef POLKIT_GRANT_DATABASE_H
#define POLKIT_GRANT_DATABASE_H

#include <polkit/polkit.h>

PolKitResult _polkit_grantdb_check_can_caller_do_action (PolKitContext         *pk_context,
                                                         PolKitAction          *action,
                                                         PolKitCaller          *caller);

polkit_bool_t _polkit_grantdb_write_keep_always (const char *action_id, uid_t uid);

polkit_bool_t _polkit_grantdb_write_keep_session (const char *action_id, const char *session_id);

polkit_bool_t _polkit_grantdb_write_pid (const char *action_id, pid_t pid);

/**
 * PolKitGrantDbGrantType:
 * @POLKIT_GRANTDB_GRANT_TYPE_PROCESS: The privilege was granted to a process
 * @POLKIT_GRANTDB_GRANT_TYPE_SESSION: The privilege was granted to session
 * @POLKIT_GRANTDB_GRANT_TYPE_ALWAYS: The privilege was granted permanently
 *
 * Defines the type and scope of a privilege grant.
 */
typedef enum {
        POLKIT_GRANTDB_GRANT_TYPE_PROCESS,
        POLKIT_GRANTDB_GRANT_TYPE_SESSION,
        POLKIT_GRANTDB_GRANT_TYPE_ALWAYS
} PolKitGrantDbGrantType;

/**
 * PolKitGrantDbForeachFunc:
 * @action_id: Identifer for the action granted
 * @uid: the UNIX process id, or -1 if the passed grant_type is not POLKIT_GRANTDB_GRANT_TYPE_ALWAYS
 * @when: when the privilege was granted
 * @grant_type: the type of grant; one of #PolKitGrantDbGrantType
 * @pid: the process id, or -1 if the passed grant_type is not POLKIT_GRANTDB_GRANT_TYPE_PROCESS
 * @pid_time: the start time of the process (only if pid is set)
 * @session_id: the session id, or NULL if the passed grant_type is not POLKIT_GRANTDB_GRANT_TYPE_SESSION
 * @user_data: user data passed to polkit_grantdb_foreach()
 *
 * Callback function for polkit_policy_cache_foreach().
 **/
typedef void (*PolKitGrantDbForeachFunc) (const char *action_id, 
                                          uid_t uid,
                                          time_t when, 
                                          PolKitGrantDbGrantType grant_type,
                                          pid_t pid, 
                                          polkit_uint64_t pid_time,
                                          const char *session_id,
                                          void *user_data);

void _polkit_grantdb_foreach (PolKitGrantDbForeachFunc callback, void *user_data);

polkit_bool_t _polkit_grantdb_delete_for_user (uid_t uid);

#endif /* POLKIT_GRANT_DATABASE_H */

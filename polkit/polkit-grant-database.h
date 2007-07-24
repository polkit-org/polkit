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

#endif /* POLKIT_GRANT_DATABASE_H */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-spawn.h : Spawn utilities
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

#if !defined (KIT_COMPILATION) && !defined(_KIT_INSIDE_KIT_H)
#error "Only <kit/kit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef KIT_SPAWN_H
#define KIT_SPAWN_H

#include <kit/kit.h>

KIT_BEGIN_DECLS

kit_bool_t kit_spawn_sync (const char  *working_directory,
                           char       **argv,
                           char       **envp,
                           char        *stdin,
                           char       **stdout,
                           char       **stderr,
                           int         *out_exit_status);

KIT_END_DECLS

#endif /* KIT_SPAWN_H */



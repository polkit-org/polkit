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

#define _POLKIT_INSIDE_POLKIT_H 1
#include <libpolkit/libpolkit-types.h>
#include <libpolkit/libpolkit-error.h>
#include <libpolkit/libpolkit-result.h>
#include <libpolkit/libpolkit-context.h>
#include <libpolkit/libpolkit-action.h>
#include <libpolkit/libpolkit-resource.h>
#include <libpolkit/libpolkit-seat.h>
#include <libpolkit/libpolkit-session.h>
#include <libpolkit/libpolkit-caller.h>
#include <libpolkit/libpolkit-policy-file-entry.h>
#include <libpolkit/libpolkit-policy-file.h>
#include <libpolkit/libpolkit-policy-cache.h>
#include <libpolkit/libpolkit-policy-default.h>
#include <libpolkit/libpolkit-module.h>
#undef _POLKIT_INSIDE_POLKIT_H

#endif /* LIBPOLKIT_H */



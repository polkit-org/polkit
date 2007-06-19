/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit.h : library for querying system-wide policy
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

#ifndef POLKIT_H
#define POLKIT_H

#define _POLKIT_INSIDE_POLKIT_H 1
#include <polkit/polkit-types.h>
#include <polkit/polkit-error.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-context.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-seat.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-policy-file-entry.h>
#include <polkit/polkit-policy-file.h>
#include <polkit/polkit-policy-cache.h>
#include <polkit/polkit-policy-default.h>
#include <polkit/polkit-module.h>
#undef _POLKIT_INSIDE_POLKIT_H

#endif /* POLKIT_H */



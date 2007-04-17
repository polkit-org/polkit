/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-seat.h : seats
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

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_SEAT_H
#define POLKIT_SEAT_H

#include <polkit/polkit-types.h>

struct PolKitSeat;
typedef struct PolKitSeat PolKitSeat;

PolKitSeat   *polkit_seat_new           (void);
PolKitSeat   *polkit_seat_ref           (PolKitSeat *seat);
void          polkit_seat_unref         (PolKitSeat *seat);
polkit_bool_t polkit_seat_set_ck_objref (PolKitSeat *seat, const char  *ck_objref);
polkit_bool_t polkit_seat_get_ck_objref (PolKitSeat *seat, char       **out_ck_objref);

void          polkit_seat_debug         (PolKitSeat *seat);
polkit_bool_t polkit_seat_validate      (PolKitSeat *seat);

#endif /* POLKIT_SEAT_H */



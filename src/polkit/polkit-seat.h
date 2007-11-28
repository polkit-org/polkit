/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-seat.h : seats
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_SEAT_H
#define POLKIT_SEAT_H

#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

struct _PolKitSeat;
typedef struct _PolKitSeat PolKitSeat;

PolKitSeat   *polkit_seat_new           (void);
PolKitSeat   *polkit_seat_ref           (PolKitSeat *seat);
void          polkit_seat_unref         (PolKitSeat *seat);
polkit_bool_t polkit_seat_set_ck_objref (PolKitSeat *seat, const char  *ck_objref);
polkit_bool_t polkit_seat_get_ck_objref (PolKitSeat *seat, char       **out_ck_objref);

void          polkit_seat_debug         (PolKitSeat *seat);
polkit_bool_t polkit_seat_validate      (PolKitSeat *seat);

POLKIT_END_DECLS

#endif /* POLKIT_SEAT_H */



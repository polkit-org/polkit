/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-seat.c : seat
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>
#include "polkit-debug.h"
#include "polkit-seat.h"
#include "polkit-utils.h"

/**
 * SECTION:polkit-seat
 * @title: Seat
 * @short_description: Represents a ConsoleKit Seat.
 *
 * This class is used to represent a seat.
 **/

/**
 * PolKitSeat:
 *
 * Objects of this class are used to record information about a
 * seat.
 **/
struct _PolKitSeat
{
        int refcount;
        char *ck_objref;
};

/**
 * polkit_seat_new:
 * 
 * Creates a new #PolKitSeat object.
 * 
 * Returns: the new object
 **/
PolKitSeat *
polkit_seat_new (void)
{
        PolKitSeat *seat;
        seat = g_new0 (PolKitSeat, 1);
        seat->refcount = 1;
        return seat;
}

/**
 * polkit_seat_ref:
 * @seat: the seat object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitSeat *
polkit_seat_ref (PolKitSeat *seat)
{
        g_return_val_if_fail (seat != NULL, seat);
        seat->refcount++;
        return seat;
}

/**
 * polkit_seat_unref:
 * @seat: the seat object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_seat_unref (PolKitSeat *seat)
{
        g_return_if_fail (seat != NULL);
        seat->refcount--;
        if (seat->refcount > 0) 
                return;
        g_free (seat->ck_objref);
        g_free (seat);
}

/**
 * polkit_seat_set_ck_objref:
 * @seat: the seat object
 * @ck_objref: the D-Bus object path to the ConsoleKit seat object
 * 
 * Set the D-Bus object path to the ConsoleKit seat object.
 *
 * Returns: #TRUE only if the value validated and was set
 **/
polkit_bool_t
polkit_seat_set_ck_objref (PolKitSeat *seat, const char *ck_objref)
{
        g_return_val_if_fail (seat != NULL, FALSE);
        g_return_val_if_fail (_pk_validate_identifier (ck_objref), FALSE);
        if (seat->ck_objref != NULL)
                g_free (seat->ck_objref);
        seat->ck_objref = g_strdup (ck_objref);
        return TRUE;
}

/**
 * polkit_seat_get_ck_objref:
 * @seat: the seat object
 * @out_ck_objref: Returns the D-Bus object path to the ConsoleKit seat object. The caller shall not free this string.
 * 
 * Get the D-Bus object path to the ConsoleKit seat object.
 * 
 * Returns: TRUE iff the value is returned
 **/
polkit_bool_t
polkit_seat_get_ck_objref (PolKitSeat *seat, char **out_ck_objref)
{
        g_return_val_if_fail (seat != NULL, FALSE);
        g_return_val_if_fail (out_ck_objref != NULL, FALSE);
        *out_ck_objref = seat->ck_objref;
        return TRUE;
}

/**
 * polkit_seat_debug:
 * @seat: the object
 * 
 * Print debug details
 **/
void
polkit_seat_debug (PolKitSeat *seat)
{
        g_return_if_fail (seat != NULL);
        _pk_debug ("PolKitSeat: refcount=%d objpath=%s", seat->refcount, seat->ck_objref);
}

/**
 * polkit_seat_validate:
 * @seat: the object
 * 
 * Validate the object
 * 
 * Returns: #TRUE iff the object is valid.
 **/
polkit_bool_t
polkit_seat_validate (PolKitSeat *seat)
{
        g_return_val_if_fail (seat != NULL, FALSE);
        g_return_val_if_fail (seat->ck_objref != NULL, FALSE);
        return TRUE;
}

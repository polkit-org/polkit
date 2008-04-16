/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-seat.c : seat
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

#include "polkit-debug.h"
#include "polkit-seat.h"
#include "polkit-utils.h"
#include "polkit-test.h"
#include "polkit-private.h"

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
        seat = kit_new0 (PolKitSeat, 1);
        if (seat == NULL)
                goto out;
        seat->refcount = 1;
out:
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
        kit_return_val_if_fail (seat != NULL, seat);
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
        kit_return_if_fail (seat != NULL);
        seat->refcount--;
        if (seat->refcount > 0) 
                return;
        kit_free (seat->ck_objref);
        kit_free (seat);
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
        kit_return_val_if_fail (seat != NULL, FALSE);
        kit_return_val_if_fail (_pk_validate_identifier (ck_objref), FALSE);
        if (seat->ck_objref != NULL)
                kit_free (seat->ck_objref);
        seat->ck_objref = kit_strdup (ck_objref);
        if (seat->ck_objref == NULL)
                return FALSE;
        else
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
        kit_return_val_if_fail (seat != NULL, FALSE);
        kit_return_val_if_fail (out_ck_objref != NULL, FALSE);
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
        kit_return_if_fail (seat != NULL);
        polkit_debug ("PolKitSeat: refcount=%d objpath=%s", seat->refcount, seat->ck_objref);
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
        kit_return_val_if_fail (seat != NULL, FALSE);
        kit_return_val_if_fail (seat->ck_objref != NULL, FALSE);
        return TRUE;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        char *str;
        PolKitSeat *s;

        s = polkit_seat_new ();
        if (s == NULL) {
                /* OOM */
        } else {
                if (! polkit_seat_set_ck_objref (s, "/someseat")) {
                        /* OOM */
                } else {
                        kit_assert (polkit_seat_get_ck_objref (s, &str) && strcmp (str, "/someseat") == 0);
                        kit_assert (polkit_seat_validate (s));
                        polkit_seat_ref (s);
                        kit_assert (polkit_seat_validate (s));
                        polkit_seat_unref (s);
                        kit_assert (polkit_seat_validate (s));
                        polkit_seat_debug (s);
                        if (! polkit_seat_set_ck_objref (s, "/someseat2")) {
                                /* OOM */
                        } else {
                                kit_assert (polkit_seat_get_ck_objref (s, &str) && strcmp (str, "/someseat2") == 0);
                        }
                }
                polkit_seat_unref (s);
        }

        return TRUE;
}

KitTest _test_seat = {
        "polkit_seat",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

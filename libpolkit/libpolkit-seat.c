/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-seat.c : seat
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
#include "libpolkit-seat.h"

struct PolKitSeat_s
{
};

PolKitSeat *
libpolkit_seat_new (void)
{
        return NULL;
}

PolKitSeat *
libpolkit_seat_ref (PolKitSeat *seat)
{
        return seat;
}

void 
libpolkit_seat_set_ck_objref (PolKitSeat *seat, const char *ck_objref)
{
}

gboolean
libpolkit_seat_get_ck_objref (PolKitSeat *seat, char **out_ck_objref)
{
        return FALSE;
}

void
libpolkit_seat_unref (PolKitSeat *seat)
{
}

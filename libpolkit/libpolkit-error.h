/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-error.h : GError error codes from PolicyKit
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

#ifndef LIBPOLKIT_ERROR_H
#define LIBPOLKIT_ERROR_H

#include <glib.h>

/**
 * PolKitError:
 * @POLKIT_ERROR_PRIVILEGE_FILE_INVALID_VALUE: There was an error parsing the given privilege file
 *
 * Error codes returned by PolicyKit
 */
typedef enum
{      
        POLKIT_ERROR_PRIVILEGE_FILE_INVALID_VALUE
} PolKitError;

/**
 * POLKIT_ERROR:
 *
 * Error domain for PolicyKit library. Errors in this domain will be
 * from the #PolKitError enumeration. See GError for details.
 **/
#define POLKIT_ERROR libpolkit_error_quark()

GQuark libpolkit_error_quark (void);


#endif /* LIBPOLKIT_RESULT_H */

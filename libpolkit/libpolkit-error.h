/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-error.h : error reporting from PolicyKit
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

/**
 * PolKitErrorCode:
 * @POLKIT_ERROR_OUT_OF_MEMORY: Out of memory
 * @POLKIT_ERROR_POLICY_FILE_INVALID: There was an error parsing the given policy file
 *
 * Error codes returned by PolicyKit
 */
typedef enum
{      
        POLKIT_ERROR_OUT_OF_MEMORY,
        POLKIT_ERROR_POLICY_FILE_INVALID
} PolKitErrorCode;

struct PolKitError;
typedef struct PolKitError PolKitError;

PolKitErrorCode  polkit_error_get_error_code (PolKitError *error);
const char      *polkit_error_get_error_message (PolKitError *error);
void             polkit_error_free (PolKitError *error);
void             polkit_error_set_error (PolKitError **error, PolKitErrorCode error_code, const char *format, ...) __attribute__((__format__ (__printf__, 3, 4)));

#endif /* LIBPOLKIT_ERROR_H */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-result.h : result codes from PolicyKit
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

#ifndef POLKIT_RESULT_H
#define POLKIT_RESULT_H

#include <polkit/polkit-types.h>

/**
 * PolKitResult:
 * @POLKIT_RESULT_UNKNOWN: The result is unknown / cannot be
 * computed. This is mostly used internally in libpolkit.
 * @POLKIT_RESULT_NO: Access denied.
 * @POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH: Access denied, but
 * authentication by the caller as administrator (e.g. root or a
 * member in the wheel group depending on configuration) will grant
 * access to the process the caller is originating from.
 * @POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION: Access denied, but
 * authentication by the caller as administrator (e.g. root or a
 * member in the wheel group depending on configuration) will grant
 * access for the remainder of the session
 * @POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS: Access denied, but
 * authentication by the caller as administrator (e.g. root or a
 * member in the wheel group depending on configuration) will grant
 * access in the future.
 * @POLKIT_RESULT_ONLY_VIA_SELF_AUTH: Access denied, but
 * authentication by the caller as himself will grant access to the
 * process the caller is originating from.
 * @POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION: Access denied, but
 * authentication by the caller as himself will grant access to the
 * resource for the remainder of the session
 * @POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS: Access denied, but
 * authentication by the caller as himself will grant access to the
 * resource in the future.
 * @POLKIT_RESULT_YES: Access granted.
 * @POLKIT_RESULT_N_RESULTS: Number of result codes
 *
 * Result codes from queries to PolicyKit. This enumeration may grow
 * in the future.
 */
typedef enum
{
        POLKIT_RESULT_UNKNOWN,

        POLKIT_RESULT_NO,

        POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH,
        POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION,
        POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS,

        POLKIT_RESULT_ONLY_VIA_SELF_AUTH,
        POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION,
        POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS,

        POLKIT_RESULT_YES,
        POLKIT_RESULT_N_RESULTS
} PolKitResult;

const char *
polkit_result_to_string_representation (PolKitResult result);

polkit_bool_t
polkit_result_from_string_representation (const char *string, PolKitResult *out_result);

#endif /* POLKIT_RESULT_H */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-result.h : result codes from PolicyKit
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

#ifndef LIBPOLKIT_RESULT_H
#define LIBPOLKIT_RESULT_H

#include <stdbool.h>

/**
 * PolKitResult:
 * @LIBPOLKIT_RESULT_UNKNOWN_ACTION: The passed action is unknown.
 * @LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW: The caller of libpolkit is not sufficiently privilege to know the answer.
 * @LIBPOLKIT_RESULT_NO: Access denied.
 * @LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH: Access denied, but authentication of the caller as 
 * root will grant access to only that caller.
 * @LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION: Access denied, but authentication of the caller as
 * root will grant access for the remainder of the session the caller stems from.
 * @LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS: Access denied, but authentication of the caller as
 * root will grant access to the user of the caller in the future.
 * @LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH: Access denied, but authentication of the caller as 
 * his user will grant access to only that caller.
 * @LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION: Access denied, but authentication of the caller as
 * his user will grant access for the remainder of the session the caller stems from.
 * @LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS: Access denied, but authentication of the caller as
 * his user will grant access to the user of the caller in the future.
 * @LIBPOLKIT_RESULT_YES: Access granted.
 * @LIBPOLKIT_RESULT_N_RESULTS: Number of result codes
 *
 * Result codes from queries to PolicyKit. These are ordered and we
 * say that a result A is "more strict" than a result B, if A has a
 * lower numerical value. (e.g. #LIBPOLKIT_RESULT_NO is more strict
 * than #LIBPOLKIT_RESULT_YES).
 */
typedef enum
{
        LIBPOLKIT_RESULT_UNKNOWN_ACTION,
        LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW,
        LIBPOLKIT_RESULT_NO,
        LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH,
        LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION,
        LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS,
        LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH,
        LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION,
        LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS,
        LIBPOLKIT_RESULT_YES,
        LIBPOLKIT_RESULT_N_RESULTS
} PolKitResult;

const char *
libpolkit_result_to_string_representation (PolKitResult result);

bool
libpolkit_result_from_string_representation (const char *string, PolKitResult *out_result);

#endif /* LIBPOLKIT_RESULT_H */

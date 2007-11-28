/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-error.h : error reporting from PolicyKit
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

#ifndef POLKIT_ERROR_H
#define POLKIT_ERROR_H

#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

/**
 * PolKitErrorCode:
 * @POLKIT_ERROR_OUT_OF_MEMORY: Out of memory
 * @POLKIT_ERROR_POLICY_FILE_INVALID: There was an error parsing the given policy file
 * @POLKIT_ERROR_GENERAL_ERROR: A general error code typically
 * indicating problems with the installation of PolicyKit,
 * e.g. helpers missing or wrong owner / permission.
 * @POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS:
 * An attempt was made to read authorizations for other users and the
 * calling process is not authorized.
 * @POLKIT_ERROR_NOT_AUTHORIZED_TO_REVOKE_AUTHORIZATIONS_FROM_OTHER_USERS:
 * An attempt was made to revoke authorizations for other users and the
 * calling process is not authorized.
 * @POLKIT_ERROR_NOT_AUTHORIZED_TO_GRANT_AUTHORIZATION: An attempt was
 * made to grant an authorization and the calling process is not
 * authorized.
 * @POLKIT_ERROR_AUTHORIZATION_ALREADY_EXISTS: Subject already has an
 * similar authorization already (modulo time of grant and who granted).
 * @POLKIT_ERROR_NOT_SUPPORTED: The operation is not supported by the
 * authorization database backend
 * @POLKIT_ERROR_NOT_AUTHORIZED_TO_MODIFY_DEFAULTS: An attempt was
 * made to modify the defaults for implicit authorizations and the
 * calling process is not authorized.
 * @POLKIT_ERROR_NUM_ERROR_CODES: Number of error codes. This may change
 * from version to version; do not rely on it.
 *
 * Errors returned by PolicyKit
 */
typedef enum
{      
        POLKIT_ERROR_OUT_OF_MEMORY,
        POLKIT_ERROR_POLICY_FILE_INVALID,
        POLKIT_ERROR_GENERAL_ERROR,
        POLKIT_ERROR_NOT_AUTHORIZED_TO_READ_AUTHORIZATIONS_FOR_OTHER_USERS,
        POLKIT_ERROR_NOT_AUTHORIZED_TO_REVOKE_AUTHORIZATIONS_FROM_OTHER_USERS,
        POLKIT_ERROR_NOT_AUTHORIZED_TO_GRANT_AUTHORIZATION,
        POLKIT_ERROR_AUTHORIZATION_ALREADY_EXISTS,
        POLKIT_ERROR_NOT_SUPPORTED,
        POLKIT_ERROR_NOT_AUTHORIZED_TO_MODIFY_DEFAULTS,

        POLKIT_ERROR_NUM_ERROR_CODES
} PolKitErrorCode;

struct _PolKitError;
typedef struct _PolKitError PolKitError;

polkit_bool_t    polkit_error_is_set (PolKitError *error);
const char      *polkit_error_get_error_name (PolKitError *error);
PolKitErrorCode  polkit_error_get_error_code (PolKitError *error);
const char      *polkit_error_get_error_message (PolKitError *error);
void             polkit_error_free (PolKitError *error);
polkit_bool_t    polkit_error_set_error (PolKitError **error, PolKitErrorCode error_code, const char *format, ...) __attribute__((__format__ (__printf__, 3, 4)));

POLKIT_END_DECLS

#endif /* POLKIT_ERROR_H */

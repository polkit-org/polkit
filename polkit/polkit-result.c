/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-result.c : result codes from PolicyKit
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

/**
 * SECTION:polkit-result
 * @short_description: Result of PolicyKit queries
 *
 * These functions are used to manipulate PolicyKit results.
 **/

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
#include "polkit-result.h"


static const struct {
        PolKitResult result;
        const char *str;
} mapping[] = 
{
        {POLKIT_RESULT_UNKNOWN, "unknown"},
        {POLKIT_RESULT_NO, "no"},
        {POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH, "auth_admin"},
        {POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_SESSION, "auth_admin_keep_session"},
        {POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH_KEEP_ALWAYS, "auth_admin_keep_always"},
        {POLKIT_RESULT_ONLY_VIA_SELF_AUTH, "auth_self"},
        {POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION, "auth_self_keep_session"},
        {POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS, "auth_self_keep_always"},
        {POLKIT_RESULT_YES, "yes"},
        {0, NULL}
};


/**
 * polkit_result_to_string_representation:
 * @result: the given result to get a textual representation of
 * 
 * Gives a textual representation of a #PolKitResult object. This
 * string is not suitable for displaying to an end user (it's not
 * localized for starters) but is useful for serialization as it can
 * be converted back to a #PolKitResult object using
 * polkit_result_from_string_representation().
 * 
 * Returns: string representing the result (do not free) or #NULL if the given result is invalid
 **/
const char *
polkit_result_to_string_representation (PolKitResult result)
{
        if (result < 0 || result >= POLKIT_RESULT_N_RESULTS) {
                g_warning ("The passed result code, %d, is not valid", result);
                return NULL;
        }

        return mapping[result].str;
}

/**
 * polkit_result_from_string_representation:
 * @string: textual representation of a #PolKitResult object
 * @out_result: return location for #PolKitResult
 * 
 * Given a textual representation of a #PolKitResult object, find the
 * #PolKitResult value.
 * 
 * Returns: TRUE if the textual representation was valid, otherwise FALSE
 **/
polkit_bool_t
polkit_result_from_string_representation (const char *string, PolKitResult *out_result)
{
        int n;

        g_return_val_if_fail (out_result != NULL, FALSE);

        for (n = 0; n < POLKIT_RESULT_N_RESULTS; n++) {
                if (mapping[n].str == NULL)
                        break;
                if (strcmp (mapping[n].str, string) == 0) {
                        *out_result = mapping[n].result;
                        goto found;
                }
        }

        return FALSE;
found:
        return TRUE;
}

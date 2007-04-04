/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * libpolkit-result.c : result codes from PolicyKit
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
 * SECTION:libpolkit-result
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
#include "libpolkit-result.h"


static const struct {
        PolKitResult result;
        const char *str;
} mapping[] = 
{
        {LIBPOLKIT_RESULT_NOT_AUTHORIZED_TO_KNOW, "not_authorized"},
        {LIBPOLKIT_RESULT_YES, "yes"},
        {LIBPOLKIT_RESULT_NO, "no"},
        {LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH, "auth_root"},
        {LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_SESSION, "auth_root_keep_session"},
        {LIBPOLKIT_RESULT_ONLY_VIA_ROOT_AUTH_KEEP_ALWAYS, "auth_root_keep_always"},
        {LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH, "auth_self"},
        {LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION, "auth_self_keep_session"},
        {LIBPOLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS, "auth_self_keep_always"},
        {0, NULL}
};


/**
 * libpolkit_result_to_string_representation:
 * @result: the given result to get a textual representation of
 * 
 * Gives a textual representation of a #PolKitResult object.
 * 
 * Returns: string representing the result (do not free) or #NULL if the given result is invalid
 **/
const char *
libpolkit_result_to_string_representation (PolKitResult result)
{
        if (result < 0 || result >= LIBPOLKIT_RESULT_N_RESULTS) {
                g_warning ("The passed result code, %d, is not valid", result);
                return NULL;
        }

        return mapping[result].str;
}

/**
 * libpolkit_result_from_string_representation:
 * @string: textual representation of a #PolKitResult object
 * @out_result: return location for #PolKitResult
 * 
 * Given a textual representation of a #PolKitResult object, find the #PolKitResult value.
 * 
 * Returns: TRUE if the textual representation was valid, otherwise FALSE
 **/
gboolean
libpolkit_result_from_string_representation (const char *string, PolKitResult *out_result)
{
        int n;

        g_return_val_if_fail (out_result != NULL, FALSE);

        for (n = 0; n < LIBPOLKIT_RESULT_N_RESULTS; n++) {
                if (mapping[n].str == NULL)
                        break;
                if (strcmp (mapping[n].str, string) == 0) {
                        *out_result = mapping[n].result;
                        goto found;
                }
        }

        /* don't print a warning; this is used by polkit-privilege-file-validate */
        return FALSE;

found:
        return TRUE;

}

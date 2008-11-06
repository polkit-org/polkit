/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include <polkit/polkit.h>

int
main (int argc, char *argv[])
{
        GList *ret;
        GError *error;
        GFile *dir;

        g_type_init ();

        dir = g_file_new_for_commandline_arg (argv[1]);

        error = NULL;
        ret = polkit_action_description_new_from_directory (dir,
                                                            NULL,
                                                            &error);
        if (error != NULL) {
                g_print ("Got error: %s\n", error->message);
                g_error_free (error);
                goto out;
        }

        g_debug ("rock'n'roll!");

        g_list_foreach (ret, (GFunc) g_object_unref, NULL);
        g_list_free (ret);

 out:
        return 0;

#if 0
        PolkitAuthorizationResult result;
        GError *error;
        PolkitAuthority *authority;

        g_type_init ();

        authority = polkit_authority_get ();

        PolkitSubject *subject1;
        PolkitSubject *subject2;
        PolkitSubject *subject3;

        subject1 = polkit_user_new ("moe");
        subject2 = polkit_user_new ("bernie");
        subject3 = polkit_process_new (42);

        GList *claims;
        claims = NULL;
        claims = g_list_prepend (claims, polkit_authorization_claim_new (subject1, "org.foo.1"));
        claims = g_list_prepend (claims, polkit_authorization_claim_new (subject2, "org.foo.2"));
        claims = g_list_prepend (claims, polkit_authorization_claim_new (subject3, "org.foo.3"));

        PolkitAuthorizationClaim *claim;
        claim = polkit_authorization_claim_new (subject3, "org.foo.4");
        polkit_authorization_claim_set_attribute (claim, "foo", "bar");
        polkit_authorization_claim_set_attribute (claim, "unix-device", "/dev/sda");
        claims = g_list_prepend (claims, claim);


        error = NULL;
        result = polkit_authority_check_claims_sync (authority,
                                                       claims,
                                                       NULL,
                                                       &error);
        if (error != NULL) {
                g_print ("Got error: %s\n", error->message);
                g_error_free (error);
        } else {
                g_print ("Got result: %d\n", result);
        }

        g_object_unref (authority);

         return 0;
#endif
}

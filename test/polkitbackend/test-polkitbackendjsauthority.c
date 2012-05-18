/*
 * Copyright (C) 2011 Google Inc.
 * Copyright (C) 2012 Red Hat, Inc.
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
 * Author: Nikki VonHollen <vonhollen@google.com>
 *         David Zeuthen <davidz@redhat.com>
 */

#include "glib.h"

#include <polkit/polkit.h>
#include <polkitbackend/polkitbackendjsauthority.h>
#include <polkittesthelper.h>

/* Test helper types */

static PolkitBackendJsAuthority *get_authority (void);

static PolkitBackendJsAuthority *
get_authority (void)
{
  gchar *rules_dir;
  PolkitBackendJsAuthority *authority;

  rules_dir = polkit_test_get_data_path ("etc/polkit-1/rules.d");
  g_assert (rules_dir != NULL);

  authority = g_object_new (POLKIT_BACKEND_TYPE_JS_AUTHORITY,
                            "rules-dir", rules_dir,
                            NULL);
  g_free (rules_dir);
  return authority;
}


static void
test_get_admin_identities_for_action_id (const gchar         *action_id,
                                         const gchar *const *expected_admins)
{
  PolkitBackendJsAuthority *authority = NULL;
  PolkitSubject *caller = NULL;
  PolkitSubject *subject = NULL;
  PolkitIdentity *user_for_subject = NULL;
  PolkitDetails *details = NULL;
  GError *error = NULL;
  GList *admin_identities = NULL;
  GList *l;
  guint n;

  authority = get_authority ();

  caller = polkit_unix_process_new (getpid ());
  subject = polkit_unix_process_new (getpid ());
  user_for_subject = polkit_identity_from_string ("unix-user:root", &error);
  g_assert_no_error (error);

  details = polkit_details_new ();

  /* Get the list of PolkitUnixUser objects who are admins */
  admin_identities = polkit_backend_interactive_authority_get_admin_identities (POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority),
                                                                                caller,
                                                                                subject,
                                                                                user_for_subject,
                                                                                action_id,
                                                                                details);
  for (l = admin_identities, n = 0; l != NULL; l = l->next, n++)
    {
      PolkitIdentity *test_identity = POLKIT_IDENTITY (l->data);
      gchar *s;

      g_assert (expected_admins[n] != NULL);

      s = polkit_identity_to_string (test_identity);
      g_assert_cmpstr (expected_admins[n], ==, s);
      g_free (s);
    }
  g_assert (expected_admins[n] == NULL);

  g_list_free_full (admin_identities, g_object_unref);
  g_clear_object (&user_for_subject);
  g_clear_object (&subject);
  g_clear_object (&caller);
  g_clear_object (&authority);
}

static void
test_get_admin_identities (void)
{
  struct {
    const gchar *action_id;
    const gchar *expected_admins[5];
  } test_cases[] = {
    {
      "com.example.doesntmatter",
      {
        "unix-group:admin",
        "unix-user:root"
      }
    },
    {
      "net.company.action1",
      {
        "unix-group:admin"
      }
    },
    {
      "net.company.action2",
      {
        "unix-group:users"
      }
    },
  };
  guint n;

  for (n = 0; n < G_N_ELEMENTS (test_cases); n++)
    {
      test_get_admin_identities_for_action_id (test_cases[n].action_id,
                                               test_cases[n].expected_admins);
    }
}


int
main (int argc, char *argv[])
{
  GIOExtensionPoint *ep;

  g_type_init ();
  g_test_init (&argc, &argv, NULL);
  //polkit_test_redirect_logs ();

  ep = g_io_extension_point_register (POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME);
  g_io_extension_point_set_required_type (ep, POLKIT_BACKEND_TYPE_AUTHORITY);

  g_test_add_func ("/PolkitBackendJsAuthority/get_admin_identities", test_get_admin_identities);

  return g_test_run ();
};

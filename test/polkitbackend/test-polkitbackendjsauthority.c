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

#include "config.h"
#include "glib.h"

#include <locale.h>
#include <string.h>

#include <polkit/polkit.h>
#include <polkitbackend/polkitbackendjsauthority.h>
#include <polkittesthelper.h>

/* see test/data/etc/polkit-1/rules.d/10-testing.rules */

/* Test helper types */

static PolkitBackendJsAuthority *get_authority (void);

static PolkitBackendJsAuthority *
get_authority (void)
{
  gchar *rules_dirs[3] = {0};
  PolkitBackendJsAuthority *authority;

  rules_dirs[0] = polkit_test_get_data_path ("etc/polkit-1/rules.d");
  rules_dirs[1] = polkit_test_get_data_path ("usr/share/polkit-1/rules.d");
  rules_dirs[2] = NULL;
  g_assert (rules_dirs[0] != NULL);
  g_assert (rules_dirs[1] != NULL);

  authority = g_object_new (POLKIT_BACKEND_TYPE_JS_AUTHORITY,
                            "rules-dirs", rules_dirs,
                            NULL);
  g_free (rules_dirs[0]);
  g_free (rules_dirs[1]);
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

  caller = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());
  subject = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());
  user_for_subject = polkit_identity_from_string ("unix-user:root", &error);
  g_assert_no_error (error);

  details = polkit_details_new ();

  /* Get the list of PolkitUnixUser objects who are admins */
  admin_identities = polkit_backend_interactive_authority_get_admin_identities (POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority),
                                                                                caller,
                                                                                subject,
                                                                                user_for_subject,
                                                                                TRUE, /* is_local */
                                                                                TRUE, /* is_active */
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
  g_assert_cmpstr (expected_admins[n], ==, NULL);

  g_list_free_full (admin_identities, g_object_unref);
  g_clear_object (&details);
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
#ifdef HAVE_SETNETGRENT
    {
      "net.company.action3",
      {
        "unix-netgroup:foo"
      }
    },
#endif
  };
  guint n;

  for (n = 0; n < G_N_ELEMENTS (test_cases); n++)
    {
      test_get_admin_identities_for_action_id (test_cases[n].action_id,
                                               test_cases[n].expected_admins);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

typedef struct RulesTestCase RulesTestCase;

struct RulesTestCase
{
  const gchar *test_name;
  const gchar *action_id;
  const gchar *identity;
  const gchar *vars;
  PolkitImplicitAuthorization expected_result;
};

static const RulesTestCase rules_test_cases[] = {
  /* Check basics */
  {
    "basic0",
    "net.company.productA.action0",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED,
  },
  {
    "basic1",
    "net.company.productA.action1",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED,
  },
  /* actions without explict rules aren't automatically NOT_AUTHORIZED */
  {
    "basic2",
    "net.company.productA.action2",
    "unix-user:john",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
  },

  /* Ordering tests ... we have four rules files, check they are
   * evaluated in order by checking the detail set by each rules
   *
   * -       etc/polkit-1/rules.d/10-testing.rules (file a)
   * - usr/share/polkit-1/rules.d/10-testing.rules (file b)
   * -       etc/polkit-1/rules.d/15-testing.rules (file c)
   * - usr/share/polkit-1/rules.d/20-testing.rules (file d)
   *
   * file.
   */
  {
    /* defined in file a, b, c, d - should pick file a */
    "order0",
    "net.company.order0",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    /* defined in file b, c, d - should pick file b */
    "order1",
    "net.company.order1",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    /* defined in file c, d - should pick file c */
    "order2",
    "net.company.order2",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },

  /* variables */
  {
    "variables1",
    "net.company.group.variables",
    "unix-user:root",
    "foo=1",
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    "variables2",
    "net.company.group.variables",
    "unix-user:root",
    "foo=2",
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED,
  },
  {
    "variables3",
    "net.company.group.variables",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED,
  },

  /* check group membership */
  {
    /* john is a member of group 'users', see test/etc/group */
    "group_membership_with_member",
    "net.company.group.only_group_users",
    "unix-user:john",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    /* sally is not a member of group 'users', see test/etc/group */
    "group_membership_with_non_member",
    "net.company.group.only_group_users",
    "unix-user:sally",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  /* check netgroup membership */
  {
    /* john is a member of netgroup 'foo', see test/etc/netgroup */
    "netgroup_membership_with_member",
    "net.company.group.only_netgroup_users",
    "unix-user:john",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    /* sally is not a member of netgroup 'foo', see test/etc/netgroup */
    "netgroup_membership_with_non_member",
    "net.company.group.only_netgroup_users",
    "unix-user:sally",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  /* spawning */
  {
    "spawning_non_existing_helper",
    "net.company.spawning.non_existing_helper",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    "spawning_successful_helper",
    "net.company.spawning.successful_helper",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    "spawning_failing_helper",
    "net.company.spawning.failing_helper",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    "spawning_helper_with_output",
    "net.company.spawning.helper_with_output",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },
  {
    "spawning_helper_timeout",
    "net.company.spawning.helper_timeout",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },

  /* runaway scripts */
  {
    "runaway_script",
    "net.company.run_away_script",
    "unix-user:root",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  {
    /* highuid1 is not a member of group 'users', see test/data/etc/group */
    "group_membership_with_non_member(highuid22)",
    "net.company.group.only_group_users",
    "unix-user:highuid2",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  {
    /* highuid2 is not a member of group 'users', see test/data/etc/group */
    "group_membership_with_non_member(highuid21)",
    "net.company.group.only_group_users",
    "unix-user:highuid2",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  {
    /* highuid1 is not a member of group 'users', see test/data/etc/group */
    "group_membership_with_non_member(highuid24)",
    "net.company.group.only_group_users",
    "unix-user:2147483648",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  {
    /* highuid2 is not a member of group 'users', see test/data/etc/group */
    "group_membership_with_non_member(highuid23)",
    "net.company.group.only_group_users",
    "unix-user:4000000000",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  {
    /* john is authorized to do this, see 10-testing.rules */
    "john_action",
    "net.company.john_action",
    "unix-user:john",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },

  {
    /* only john is authorized to do this, see 10-testing.rules */
    "jane_action",
    "net.company.john_action",
    "unix-user:jane",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },

  {
    /* highuid2 is authorized to do this, see 10-testing.rules */
    "highuid2_action",
    "net.company.highuid2_action",
    "unix-user:highuid2",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED,
  },

  {
    /* only highuid2 is authorized to do this, see 10-testing.rules */
    "highuid1_action",
    "net.company.highuid2_action",
    "unix-user:highuid1",
    NULL,
    POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED,
  },
};

/* ---------------------------------------------------------------------------------------------------- */

static void
rules_test_func (gconstpointer user_data)
{
  const RulesTestCase *tc = user_data;
  PolkitBackendJsAuthority *authority = NULL;
  PolkitSubject *caller = NULL;
  PolkitSubject *subject = NULL;
  PolkitIdentity *user_for_subject = NULL;
  PolkitDetails *details = NULL;
  GError *error = NULL;
  PolkitImplicitAuthorization result;

  authority = get_authority ();

  caller = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());
  subject = polkit_unix_process_new_for_owner (getpid (), 0, getuid ());
  user_for_subject = polkit_identity_from_string (tc->identity, &error);
  g_assert_no_error (error);

  details = polkit_details_new ();

  if (tc->vars != NULL)
    {
      gchar *s;
      const gchar *key;
      const gchar *value;

      s = g_strdup (tc->vars);
      key = s;
      value = strchr (key, '=');
      g_assert (value != NULL);
      *((gchar *) value) = '\0';
      value += 1;

      polkit_details_insert (details, key, value);
      g_free (s);
    }

  result = polkit_backend_interactive_authority_check_authorization_sync (POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority),
                                                                          caller,
                                                                          subject,
                                                                          user_for_subject,
                                                                          TRUE,
                                                                          TRUE,
                                                                          tc->action_id,
                                                                          details,
                                                                          POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN);
  g_assert_cmpint (result, ==, tc->expected_result);

  g_clear_object (&details);
  g_clear_object (&user_for_subject);
  g_clear_object (&subject);
  g_clear_object (&caller);
  g_clear_object (&authority);
}

static void
add_rules_tests (void)
{
  guint n;
  for (n = 0; n < G_N_ELEMENTS (rules_test_cases); n++)
    {
      const RulesTestCase *tc = &rules_test_cases[n];
      gchar *s;
      s = g_strdup_printf ("/PolkitBackendJsAuthority/rules_%s", tc->test_name);
      g_test_add_data_func (s, &rules_test_cases[n], rules_test_func);
      g_free (s);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

int
main (int argc, char *argv[])
{
  setlocale (LC_ALL, "");

  g_test_init (&argc, &argv, NULL);
  //polkit_test_redirect_logs ();

  g_test_add_func ("/PolkitBackendJsAuthority/get_admin_identities", test_get_admin_identities);
  add_rules_tests ();

  return g_test_run ();
};

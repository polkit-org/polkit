/*
 * Copyright (C) 2011 Google Inc.
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
 */

#include "glib.h"
#include <polkit/polkit.h>
#include <polkit/polkitprivate.h>

/* Test helper types */

struct ComparisonTestData {
  const gchar *subject_a;
  const gchar *subject_b;
  gboolean equal;
};


/* Test definitions */

static void
test_string (const void *_subject)
{
  const gchar *subject = (const gchar *) _subject;

  PolkitIdentity *identity;
  GError *error = NULL;
  gchar *subject_new;

  /* Create the subject from a string */
  identity = polkit_identity_from_string (subject, &error);
  g_assert (identity);
  g_assert_no_error (error);

  /* Create new string for identity */
  subject_new = polkit_identity_to_string (identity);

  /* Make sure they match */
  g_assert_cmpstr (subject_new, ==, subject);

  g_free (subject_new);
  g_object_unref (identity);
}


static void
test_gvariant (const void *_subject)
{
  const gchar *subject = (const gchar *) _subject;

  PolkitIdentity *identity, *new_identity;
  GError *error = NULL;
  GVariant *value;

  /* Create the subject from a string */
  identity = polkit_identity_from_string (subject, &error);
  g_assert_no_error (error);
  g_assert (identity);

  /* Create a GVariant for the subject */
  value = polkit_identity_to_gvariant (identity);
  g_assert (value);

  /* Unserialize the subject */
  new_identity = polkit_identity_new_for_gvariant (value, &error);
  g_assert_no_error (error);
  g_assert (new_identity);
  g_variant_unref (value);

  /* Make sure the two identities are equal */
  g_assert (new_identity);
  g_assert (polkit_identity_equal (identity, new_identity));

  g_object_unref (identity);
  g_object_unref (new_identity);
}


static void
test_comparison (const void *_data)
{
  struct ComparisonTestData *data = (struct ComparisonTestData *) _data;

  PolkitIdentity *identity_a, *identity_b;
  GError *error = NULL;
  guint hash_a, hash_b;

  /* Create identities A and B */
  identity_a = polkit_identity_from_string (data->subject_a, &error);
  g_assert_no_error (error);
  g_assert (identity_a);

  identity_b = polkit_identity_from_string (data->subject_b, &error);
  g_assert_no_error (error);
  g_assert (identity_b);

  /* Compute their hashes */
  hash_a = polkit_identity_hash (identity_a);
  hash_b = polkit_identity_hash (identity_b);

  /* Comparison to self should always work */
  g_assert (polkit_identity_equal (identity_a, identity_a));

  /* Are A and B supposed to match? Test hash and comparators */
  if (data->equal)
  {
    g_assert_cmpint (hash_a, ==, hash_b);
    g_assert (polkit_identity_equal (identity_a, identity_b));
  }
  else
  {
    g_assert_cmpint (hash_a, !=, hash_b);
    g_assert (!polkit_identity_equal (identity_a, identity_b));
  }

  g_object_unref (identity_a);
  g_object_unref (identity_b);
}


/* Test helpers */

struct ComparisonTestData comparison_test_data [] = {
  {"unix-user:root", "unix-user:root", TRUE},
  {"unix-user:root", "unix-user:john", FALSE},
  {"unix-user:john", "unix-user:john", TRUE},

  {"unix-group:root", "unix-group:root", TRUE},
  {"unix-group:root", "unix-group:jane", FALSE},
  {"unix-group:jane", "unix-group:jane", TRUE},

#ifdef HAVE_SETNETGRENT
  {"unix-netgroup:foo", "unix-netgroup:foo", TRUE},
  {"unix-netgroup:foo", "unix-netgroup:bar", FALSE},
#endif

  {"unix-user:root", "unix-group:root", FALSE},
#ifdef HAVE_SETNETGRENT
  {"unix-user:jane", "unix-netgroup:foo", FALSE},
#endif

  {NULL},
};

static void
add_comparison_tests (void)
{
  unsigned int i;
  for (i = 0; comparison_test_data[i].subject_a != NULL; i++)
  {
    struct ComparisonTestData *test_data = &comparison_test_data[i];
    gchar *test_name = g_strdup_printf ("/PolkitIdentity/comparison_%d", i);
    g_test_add_data_func (test_name, test_data, test_comparison);
  }
}


int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_data_func ("/PolkitIdentity/user_string_0", "unix-user:root", test_string);
  g_test_add_data_func ("/PolkitIdentity/user_string_1", "unix-user:john", test_string);
  g_test_add_data_func ("/PolkitIdentity/user_string_2", "unix-user:jane", test_string);

  g_test_add_data_func ("/PolkitIdentity/group_string_0", "unix-group:root", test_string);
  g_test_add_data_func ("/PolkitIdentity/group_string_1", "unix-group:john", test_string);
  g_test_add_data_func ("/PolkitIdentity/group_string_2", "unix-group:jane", test_string);
  g_test_add_data_func ("/PolkitIdentity/group_string_3", "unix-group:users", test_string);

#ifdef HAVE_SETNETGRENT
  g_test_add_data_func ("/PolkitIdentity/netgroup_string", "unix-netgroup:foo", test_string);
  g_test_add_data_func ("/PolkitIdentity/netgroup_gvariant", "unix-netgroup:foo", test_gvariant);
#endif

  g_test_add_data_func ("/PolkitIdentity/user_gvariant", "unix-user:root", test_gvariant);
  g_test_add_data_func ("/PolkitIdentity/group_gvariant", "unix-group:root", test_gvariant);

  add_comparison_tests ();

  return g_test_run ();
}

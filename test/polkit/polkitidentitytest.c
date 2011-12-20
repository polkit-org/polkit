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


static void
test_user_from_string (void)
{
  PolkitIdentity *identity;
  PolkitUnixUser *user;
  GError *error = NULL;

  identity = polkit_identity_from_string ("unix-user:root", &error);
  g_assert (identity);
  g_assert_no_error (error);
  g_assert (POLKIT_IS_UNIX_USER (identity));

  user = POLKIT_UNIX_USER (identity);
  g_assert (user);

  g_object_unref (user);
}


static void
test_group_from_string (void)
{
  PolkitIdentity *identity;
  PolkitUnixGroup *group;
  GError *error = NULL;

  identity = polkit_identity_from_string ("unix-group:root", &error);
  g_assert (identity);
  g_assert_no_error (error);
  g_assert (POLKIT_IS_UNIX_GROUP (identity));

  group = POLKIT_UNIX_GROUP (identity);
  g_assert (group);

  g_object_unref (group);
}


static void
test_user_to_string (void)
{
  PolkitIdentity *identity;
  GError *error = NULL;
  gchar *value;

  identity = polkit_identity_from_string ("unix-user:root", &error);
  g_assert (identity);
  g_assert_no_error (error);

  value = polkit_identity_to_string (identity);
  g_assert_cmpstr (value, ==, "unix-user:root");

  g_free (value);
  g_object_unref (identity);
}


static void
test_group_to_string (void)
{
  PolkitIdentity *identity;
  GError *error = NULL;
  gchar *value;

  identity = polkit_identity_from_string ("unix-group:root", &error);
  g_assert (identity);
  g_assert_no_error (error);

  value = polkit_identity_to_string (identity);
  g_assert_cmpstr (value, ==, "unix-group:root");

  g_free (value);
  g_object_unref (identity);
}


static void
test_equal (void)
{
  PolkitIdentity *identity_a, *identity_b;
  GError *error = NULL;

  identity_a = polkit_identity_from_string ("unix-group:root", &error);
  identity_b = polkit_identity_from_string ("unix-group:root", &error);
  g_assert (polkit_identity_equal (identity_a, identity_b));

  g_object_unref (identity_a);
  g_object_unref (identity_b);
}


static void
test_hash (void)
{
  PolkitIdentity *identity_a, *identity_b;
  guint hash_a, hash_b;
  GError *error = NULL;

  identity_a = polkit_identity_from_string ("unix-group:root", &error);
  identity_b = polkit_identity_from_string ("unix-group:root", &error);

  hash_a = polkit_identity_hash (identity_a);
  hash_b = polkit_identity_hash (identity_b);
  g_assert_cmpint (hash_a, ==, hash_b);

  g_object_unref (identity_a);
  g_object_unref (identity_b);
}


int
main (int argc, char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/PolkitIdentity/user_from_string", test_user_from_string);
  g_test_add_func ("/PolkitIdentity/user_to_string", test_user_to_string);
  g_test_add_func ("/PolkitIdentity/group_from_string", test_group_from_string);
  g_test_add_func ("/PolkitIdentity/group_to_string", test_group_to_string);
  g_test_add_func ("/PolkitIdentity/equal", test_equal);
  g_test_add_func ("/PolkitIdentity/hash", test_hash);
  return g_test_run ();
}

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
test_new (void)
{
  PolkitUnixUser *user;

  user = POLKIT_UNIX_USER (polkit_unix_user_new (0));
  g_assert (user);

  gint user_uid = polkit_unix_user_get_uid (user);
  g_assert_cmpint (user_uid, ==, 0);

  g_object_unref (user);
}


static void
test_new_for_name (void)
{
  GError *error = NULL;
  PolkitUnixUser *user;

  user = POLKIT_UNIX_USER (polkit_unix_user_new_for_name ("root", &error));
  g_assert (user);
  g_assert_no_error (error);

  gint user_uid = polkit_unix_user_get_uid (user);
  g_assert_cmpint (user_uid, ==, 0);

  g_object_unref (user);
}


static void
test_set_uid (void)
{
  PolkitUnixUser *user;
  user = POLKIT_UNIX_USER (polkit_unix_user_new (0));

  polkit_unix_user_set_uid (user, 5);

  gint user_uid = polkit_unix_user_get_uid (user);
  g_assert_cmpint (user_uid, ==, 5);

  g_object_unref (user);
}


int
main (int argc, char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/PolkitUnixUser/new", test_new);
  g_test_add_func ("/PolkitUnixUser/new_for_name", test_new_for_name);
  g_test_add_func ("/PolkitUnixUser/set_uid", test_set_uid);
  return g_test_run ();
}

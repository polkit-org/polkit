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
  PolkitUnixGroup *group;

  group = POLKIT_UNIX_GROUP (polkit_unix_group_new (0));
  g_assert (group);

  gint group_gid = polkit_unix_group_get_gid (group);
  g_assert_cmpint (group_gid, ==, 0);

  g_object_unref (group);
}


static void
test_new_for_name (void)
{
  GError *error = NULL;
  PolkitUnixGroup *group;

  group = POLKIT_UNIX_GROUP (polkit_unix_group_new_for_name ("root", &error));
  g_assert (group);
  g_assert_no_error (error);

  gint group_gid = polkit_unix_group_get_gid (group);
  g_assert_cmpint (group_gid, ==, 0);

  g_object_unref (group);
}


static void
test_set_gid (void)
{
  PolkitUnixGroup *group;
  group = POLKIT_UNIX_GROUP (polkit_unix_group_new (0));

  polkit_unix_group_set_gid (group, 5);

  gint group_gid = polkit_unix_group_get_gid (group);
  g_assert_cmpint (group_gid, ==, 5);

  g_object_unref (group);
}


int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/PolkitUnixGroup/new", test_new);
  g_test_add_func ("/PolkitUnixGroup/new_for_name", test_new_for_name);
  g_test_add_func ("/PolkitUnixGroup/set_gid", test_set_gid);
  return g_test_run ();
}

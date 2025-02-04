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
#include <string.h>

#ifdef HAVE_SETNETGRENT
static void
test_new (void)
{
  PolkitUnixNetgroup *netgroup;
  const char *netgroup_name;

  netgroup = POLKIT_UNIX_NETGROUP (polkit_unix_netgroup_new ("testgroup"));
  g_assert (netgroup);

  netgroup_name = polkit_unix_netgroup_get_name (netgroup);
  g_assert_cmpstr (netgroup_name, ==, "testgroup");

  g_object_unref (netgroup);
}


static void
test_set_name (void)
{
  PolkitUnixNetgroup *netgroup;
  const char *netgroup_name;
  char new_name_buf [] = "foo";

  netgroup = POLKIT_UNIX_NETGROUP (polkit_unix_netgroup_new ("testgroup"));

  polkit_unix_netgroup_set_name (netgroup, new_name_buf);
  netgroup_name = polkit_unix_netgroup_get_name (netgroup);
  g_assert_cmpstr (netgroup_name, ==, "foo");

  memcpy(new_name_buf, "bar", 3);
  netgroup_name = polkit_unix_netgroup_get_name (netgroup);
  g_assert_cmpstr (netgroup_name, ==, "foo");

  polkit_unix_netgroup_set_name (netgroup, new_name_buf);
  netgroup_name = polkit_unix_netgroup_get_name (netgroup);
  g_assert_cmpstr (netgroup_name, ==, "bar");

  g_object_unref (netgroup);
}
#endif

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
#ifdef HAVE_SETNETGRENT
  g_test_add_func ("/PolkitUnixNetgroup/new", test_new);
  g_test_add_func ("/PolkitUnixNetgroup/set_name", test_set_name);
#endif
  return g_test_run ();
}

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

#include <polkittesthelper.h>
#include <polkit/polkit.h>
#include <polkitbackend/polkitbackendlocalauthorizationstore.h>

#define DATA_DIR "./data/authstore1/10-test"
#define DATA_EXT ".pkla"

static void
test_new (void)
{
  PolkitBackendLocalAuthorizationStore *store;
  GFile *data_dir;

  data_dir = g_file_new_for_path (DATA_DIR);

  store = polkit_backend_local_authorization_store_new (data_dir, DATA_EXT);
  g_assert (store);
}


static void
test_lookup (void)
{
  GFile *data_dir;
  PolkitBackendLocalAuthorizationStore *store;
  GError *error = NULL;
  PolkitIdentity *identity;
  gboolean ok;
  PolkitImplicitAuthorization ret_any;
  PolkitImplicitAuthorization ret_inactive;
  PolkitImplicitAuthorization ret_active;
  PolkitDetails *details;

  // Create the auth store
  data_dir = g_file_new_for_path (DATA_DIR);
  store = polkit_backend_local_authorization_store_new (data_dir, DATA_EXT);
  g_assert (store);

  // We don't care about details
  details = polkit_details_new ();

  // Create an identity to query with
  identity = polkit_identity_from_string("unix-group:users", &error);
  g_assert (identity);
  g_assert_no_error (error);

  // Lookup an exisiting record
  ok = polkit_backend_local_authorization_store_lookup (
      store,
      identity,
      "com.example.awesomeproduct.dofoo",
      details,
      &ret_any,
      &ret_inactive,
      &ret_active,
      NULL);
  g_assert (ok);
  g_assert_cmpstr ("no", ==, polkit_implicit_authorization_to_string (ret_any));
  g_assert_cmpstr ("auth_self", ==, polkit_implicit_authorization_to_string (ret_inactive));
  g_assert_cmpstr ("yes", ==, polkit_implicit_authorization_to_string (ret_active));

  // Create another identity to query with
  identity = polkit_identity_from_string("unix-user:root", &error);
  g_assert (identity);
  g_assert_no_error (error);

  // Lookup another exisiting record
  ok = polkit_backend_local_authorization_store_lookup (
      store,
      identity,
      "com.example.awesomeproduct.dofoo",
      details,
      &ret_any,
      &ret_inactive,
      &ret_active,
      NULL);
  g_assert (ok);
  g_assert_cmpstr ("no", ==, polkit_implicit_authorization_to_string (ret_any));
  g_assert_cmpstr ("auth_self", ==, polkit_implicit_authorization_to_string (ret_inactive));
  g_assert_cmpstr ("yes", ==, polkit_implicit_authorization_to_string (ret_active));

  // Lookup a missing record
  ok = polkit_backend_local_authorization_store_lookup (
      store,
      identity,
      "com.example.restrictedproduct.dobar",
      details,
      &ret_any,
      &ret_inactive,
      &ret_active,
      NULL);
  g_assert (!ok);
}


int
main (int argc, char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);
  polkit_test_redirect_logs ();
  g_test_add_func ("/PolkitBackendLocalAuthorizationStore/new", test_new);
  g_test_add_func ("/PolkitBackendLocalAuthorizationStore/lookup", test_lookup);
  return g_test_run ();
}

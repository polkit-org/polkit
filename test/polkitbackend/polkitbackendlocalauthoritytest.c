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
#include <polkitbackend/polkitbackendlocalauthority.h>

#define TEST_CONFIG_PATH "./data/config"
#define TEST_AUTH_PATH1 "./data/authstore1"
#define TEST_AUTH_PATH2 "./data/authstore2"

/* Test helper types */

struct auth_context {
  const gchar *identity;
  gboolean subject_is_local;
  gboolean subject_is_active;
  const gchar *action_id;
  PolkitImplicitAuthorization implicit;
  PolkitImplicitAuthorization expect;
};

static PolkitBackendLocalAuthority *create_authority (void);


/* Test implementations */

static void
test_check_authorization_sync (const void *_ctx)
{
  const struct auth_context *ctx = (const struct auth_context *) _ctx;

  PolkitBackendLocalAuthority *authority = create_authority ();

  PolkitSubject *caller = polkit_unix_session_new ("caller-session");
  g_assert (caller);

  PolkitSubject *subject = polkit_unix_session_new ("subject-session");;
  g_assert (subject);

  GError *error = NULL;
  PolkitIdentity *user_for_subject = polkit_identity_from_string (ctx->identity, &error);
  g_assert_no_error (error);
  g_assert (user_for_subject);

  PolkitDetails *details = polkit_details_new ();
  g_assert (details);

  PolkitDetails *out_details = polkit_details_new ();
  g_assert (out_details);

  PolkitImplicitAuthorization auth;

  auth = polkit_backend_interactive_authority_check_authorization_sync (
      POLKIT_BACKEND_INTERACTIVE_AUTHORITY (authority),
      caller,
      subject,
      user_for_subject,
      ctx->subject_is_local,
      ctx->subject_is_active,
      ctx->action_id,
      details,
      ctx->implicit,
      out_details);

  g_assert_cmpint (auth, ==, ctx->expect);

  g_object_unref (authority);
  g_object_unref (caller);
  g_object_unref (subject);
  g_object_unref (user_for_subject);
  g_object_unref (details);
  g_object_unref (out_details);
}


/* Factory for mock local authority. */
static PolkitBackendLocalAuthority *
create_authority (void)
{
  return g_object_new (
      POLKIT_BACKEND_TYPE_LOCAL_AUTHORITY,
      "config-path", TEST_CONFIG_PATH,
      "auth-store-paths", TEST_AUTH_PATH1 ";" TEST_AUTH_PATH2,
      NULL);
}


/* Variations of the check_authorization_sync */
struct auth_context check_authorization_test_data [] = {
  {"unix-user:root", TRUE, TRUE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHORIZED},
  {"unix-user:root", TRUE, FALSE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED},
  {"unix-user:root", FALSE, FALSE, "com.example.awesomeproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_NOT_AUTHORIZED},
  {"unix-user:root", TRUE, TRUE, "com.example.restrictedproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED},
  {"unix-user:root", TRUE, TRUE, "com.example.missingproduct.foo",
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN,
      POLKIT_IMPLICIT_AUTHORIZATION_UNKNOWN},
  {NULL},
};


/* Automatically create many variations of the check_authorization_sync test */
static void
add_check_authorization_tests (void) {
  unsigned int i;
  for (i = 0; check_authorization_test_data[i].identity; i++) {
    struct auth_context *ctx = &check_authorization_test_data[i];
    gchar *test_name = g_strdup_printf (
        "/PolkitBackendLocalAuthority/check_authorization_sync_%d", i);
    g_test_add_data_func(test_name, ctx, test_check_authorization_sync);
  }
};


int
main (int argc, char *argv[])
{
  g_type_init ();
  g_test_init (&argc, &argv, NULL);
  polkit_test_redirect_logs ();

  // Register extension point only once. Required to create authority.
  GIOExtensionPoint *ep = g_io_extension_point_register (
      POLKIT_BACKEND_AUTHORITY_EXTENSION_POINT_NAME);
  g_io_extension_point_set_required_type (ep,
      POLKIT_BACKEND_TYPE_AUTHORITY);

  add_check_authorization_tests ();
  return g_test_run ();
};

/*
 * Copyright (C) 2026 Amutable
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
 */

#include "glib.h"
#include <polkit/polkit.h>

static PolkitSubject *
new_process (const gchar *on_behalf_of)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_PROCESS,
                                       "pid", 1234,
                                       "start_time", (guint64) 42,
                                       "uid", 500,
                                       "on-behalf-of", on_behalf_of,
                                       NULL));
}

/* A proxy serves many callers from one pid; a subject tagged for one
 * caller must never compare equal to one tagged for another, or
 * temporary authorizations leak between them. */
static void
test_equal_on_behalf_of (void)
{
  PolkitSubject *plain = new_process (NULL);
  PolkitSubject *plain2 = new_process (NULL);
  PolkitSubject *a = new_process ("0123456789abcdef/caller-tag/p");
  PolkitSubject *a2 = new_process ("0123456789abcdef/caller-tag/p");
  PolkitSubject *b = new_process ("fedcba9876543210/caller-tag/p");

  g_assert_true (polkit_subject_equal (plain, plain2));
  g_assert_true (polkit_subject_equal (a, a2));
  g_assert_cmpuint (polkit_subject_hash (a), ==, polkit_subject_hash (a2));

  g_assert_false (polkit_subject_equal (a, b));
  g_assert_false (polkit_subject_equal (b, a));
  g_assert_false (polkit_subject_equal (plain, a));
  g_assert_false (polkit_subject_equal (a, plain));

  g_object_unref (plain);
  g_object_unref (plain2);
  g_object_unref (a);
  g_object_unref (a2);
  g_object_unref (b);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/PolkitUnixProcess/equal_on_behalf_of", test_equal_on_behalf_of);
  return g_test_run ();
}

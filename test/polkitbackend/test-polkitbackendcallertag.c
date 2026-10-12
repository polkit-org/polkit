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

#include <glib.h>
#include <polkitbackend/polkitbackendcallertag.h>

/* The provider part becomes a path component under a root-owned directory,
 * so rejecting anything that could escape it is the point of this parser. */
static const struct {
  const gchar *tag;
  const gchar *reference;   /* NULL: must be rejected */
  const gchar *provider;
} cases[] = {
  { "0123456789abcdef/caller-tag/io.systemd.VarlinkBridge", "0123456789abcdef", "io.systemd.VarlinkBridge" },
  { "ABCDEF0123456789/caller-tag/a-b_c.d",                  "ABCDEF0123456789", "a-b_c.d" },
  { "0123456789abcdef0/caller-tag/p",                        "0123456789abcdef0", "p" },   /* longer is fine */

  { "",                                                   NULL, NULL },
  { "0123456789abcdef",                                   NULL, NULL },   /* no segment */
  { "/caller-tag/p",                                      NULL, NULL },   /* empty reference */
  { "1/caller-tag/p",                                     NULL, NULL },   /* reference too short */
  { "0123456789abcde/caller-tag/p",                       NULL, NULL },
  { "0123456789abcdeg/caller-tag/p",                      NULL, NULL },   /* reference not hex */
  { "0123456789abcdef/bus/systemd/bus-system",            NULL, NULL },   /* sd-bus shape, not ours */
  { "0123456789abcdef/caller-tag",                        NULL, NULL },   /* no trailing slash */
  { "0123456789abcdef/caller-tag/",                       NULL, NULL },   /* empty provider */
  { "0123456789abcdef/caller-tag/a/b",                    NULL, NULL },   /* nested path */
  { "0123456789abcdef/caller-tag/..",                     NULL, NULL },
  { "0123456789abcdef/caller-tag/../../etc/passwd",       NULL, NULL },
  { "0123456789abcdef/caller-tag/a..b",                   NULL, NULL },
  { "0123456789abcdef/caller-tag/a b",                    NULL, NULL },   /* outside the alphabet */
  { "0123456789abcdef/caller-tag/a\x01b",                 NULL, NULL },
};

static void
test_parse_too_long (void)
{
  gchar *reference = g_strnfill (300, 'a');
  gchar *tag = g_strconcat (reference, "/caller-tag/p", NULL);
  gchar *ret_reference = NULL;
  gchar *ret_provider = NULL;
  GError *error = NULL;

  g_assert_false (polkit_backend_caller_tag_parse (tag, &ret_reference, &ret_provider, &error));
  g_assert_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
  g_assert_null (ret_reference);
  g_assert_null (ret_provider);

  g_error_free (error);
  g_free (tag);
  g_free (reference);
}

static void
test_parse (void)
{
  gsize i;

  for (i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      gchar *reference = NULL;
      gchar *provider = NULL;
      GError *error = NULL;
      gboolean ok;

      ok = polkit_backend_caller_tag_parse (cases[i].tag, &reference, &provider, &error);

      if (cases[i].reference != NULL)
        {
          g_assert_true (ok);
          g_assert_no_error (error);
          g_assert_cmpstr (reference, ==, cases[i].reference);
          g_assert_cmpstr (provider, ==, cases[i].provider);
        }
      else
        {
          g_assert_false (ok);
          g_assert_nonnull (error);
          g_assert_null (reference);
          g_assert_null (provider);
          g_error_free (error);
        }

      g_free (reference);
      g_free (provider);
    }
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/PolkitBackend/CallerTag/parse", test_parse);
  g_test_add_func ("/PolkitBackend/CallerTag/parse_too_long", test_parse_too_long);
  return g_test_run ();
}

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

#include "polkittesthelper.h"
#include <stdlib.h>


/* TODO: Log handling with unit tests is horrible. Figure out a way to always
 *       show logs, without munging up test output. For now, we hide them
 *       unless --verbose is used with g_test_message(...).
 */

void
polkit_test_log_handler (const gchar *log_domain,
                         GLogLevelFlags log_level,
                         const gchar *message,
                         gpointer user_data)
{
  g_test_message("%s", message);
}

/**
 * Send all future log messages to g_test_message(...).
 *
 * Logs will only be shown when test programs are run with --verbose.
 */
void
polkit_test_redirect_logs (void)
{
  g_log_set_default_handler (polkit_test_log_handler, NULL);
}

/**
 * Get absolute path to test data.
 *
 * Requires POLKIT_TEST_DATA environment variable to point to root data dir.
 *
 * @param relpath Relative path to test data
 * @return Full path to data as string. Free with g_free().
 */
gchar *
polkit_test_get_data_path (const gchar *relpath)
{
  const gchar *root = getenv ("POLKIT_TEST_DATA");
  if (root == NULL)
    return NULL;

  return g_strconcat(root, "/", relpath, NULL);
}


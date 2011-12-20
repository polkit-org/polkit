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

#ifndef POLKIT_TEST_HELPER_H_
#define POLKIT_TEST_HELPER_H_

#include "glib.h"

void polkit_test_log_handler (const gchar *log_domain,
                              GLogLevelFlags log_level,
                              const gchar *message,
                              gpointer user_data);

void polkit_test_redirect_logs (void);

gchar *polkit_test_get_data_path (const gchar *relpath);

#endif

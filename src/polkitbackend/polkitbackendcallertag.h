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

#ifndef __POLKIT_BACKEND_CALLER_TAG_H
#define __POLKIT_BACKEND_CALLER_TAG_H

#include <gio/gio.h>
#include <polkit/polkit.h>

G_BEGIN_DECLS

gboolean polkit_backend_caller_tag_parse (const gchar  *tag,
                                          gchar       **ret_reference,
                                          gchar       **ret_provider,
                                          GError      **error);

gchar *polkit_backend_caller_tag_resolve (const gchar        *tag,
                                          PolkitUnixProcess  *subject,
                                          GError            **error);

G_END_DECLS

#endif /* __POLKIT_BACKEND_CALLER_TAG_H */

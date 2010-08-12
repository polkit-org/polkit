/*
 * Copyright (C) 2008 Red Hat, Inc.
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
 * Author: David Zeuthen <davidz@redhat.com>
 */

#if !defined(_POLKIT_AGENT_INSIDE_POLKIT_AGENT_H) && !defined (_POLKIT_AGENT_COMPILATION)
#error "Only <polkitagent/polkitagent.h> can be included directly, this file may disappear or change contents"
#endif

#ifndef __POLKIT_AGENT_TEXT_LISTENER_H
#define __POLKIT_AGENT_TEXT_LISTENER_H

#include <polkit/polkit.h>
#include <polkitagent/polkitagenttypes.h>

G_BEGIN_DECLS

#define POLKIT_AGENT_TYPE_TEXT_LISTENER          (polkit_agent_text_listener_get_type())
#define POLKIT_AGENT_TEXT_LISTENER(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_AGENT_TYPE_TEXT_LISTENER, PolkitAgentTextListener))
#define POLKIT_AGENT_IS_TEXT_LISTENER(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_AGENT_TYPE_TEXT_LISTENER))

GType                polkit_agent_text_listener_get_type (void) G_GNUC_CONST;
PolkitAgentListener *polkit_agent_text_listener_new      (GCancellable   *cancellable,
                                                          GError        **error);


G_END_DECLS

#endif /* __POLKIT_AGENT_TEXT_LISTENER_H */

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

#ifndef __POLKIT_AGENT_AUTHENTICATION_AGENT_H
#define __POLKIT_AGENT_AUTHENTICATION_AGENT_H

#include <polkit/polkit.h>
#include <polkitagent/polkitagenttypes.h>

G_BEGIN_DECLS

#define POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT         (polkit_agent_authentication_agent_get_type ())
#define POLKIT_AGENT_AUTHENTICATION_AGENT(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT, PolkitAgentAuthenticationAgent))
#define POLKIT_AGENT_AUTHENTICATION_AGENT_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST ((k), POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT, PolkitAgentAuthenticationAgentClass))
#define POLKIT_AGENT_AUTHENTICATION_AGENT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT,PolkitAgentAuthenticationAgentClass))
#define POLKIT_AGENT_IS_AUTHENTICATION_AGENT(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT))
#define POLKIT_AGENT_IS_AUTHENTICATION_AGENT_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT))

#if 0
typedef struct _PolkitAgentAuthenticationAgent PolkitAgentAuthenticationAgent;
#endif
typedef struct _PolkitAgentAuthenticationAgentClass    PolkitAgentAuthenticationAgentClass;

/* TODO: we probably want to express this interface in another way but this is good enough for now */

typedef void (*PolkitAgentAuthenticationAgentBeginFunc) (PolkitAgentAuthenticationAgent *agent,
                                                         const gchar                    *action_id,
                                                         const gchar                    *cookie,
                                                         GList                          *identities,
                                                         gpointer                        pending_call);

typedef void (*PolkitAgentAuthenticationAgentCancelFunc)   (PolkitAgentAuthenticationAgent *agent,
                                                            const gchar                    *cookie,
                                                            gpointer                        user_data);

GType                           polkit_agent_authentication_agent_get_type (void) G_GNUC_CONST;

PolkitAgentAuthenticationAgent *polkit_agent_authentication_agent_new (PolkitAgentAuthenticationAgentBeginFunc begin_func,
                                                                       PolkitAgentAuthenticationAgentCancelFunc cancel_func,
                                                                       gpointer user_data,
                                                                       GError **error);

void                            polkit_agent_authentication_agent_finish (PolkitAgentAuthenticationAgent *agent,
                                                                          gpointer                        pending_call,
                                                                          GError                         *error);

/* --- */

G_END_DECLS

#endif /* __POLKIT_AGENT_AUTHENTICATION_AGENT_H */

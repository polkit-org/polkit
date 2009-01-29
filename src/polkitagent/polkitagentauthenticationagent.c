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

#include "config.h"

#include <polkit/polkitprivate.h>
#include "_polkitagentbindings.h"

#include "polkitagentauthenticationagent.h"

/**
 * SECTION:polkitagentauthenticationagent
 * @title: PolkitAgentAuthenticationAgent
 * @short_description: Authentication Agent
 *
 * The #PolkitAgentAuthenticationAgent class is used for implementing authentication agents.
 */

struct _PolkitAgentAuthenticationAgent
{
  GObject parent_instance;

  EggDBusConnection *system_bus;

  EggDBusObjectProxy *authority_proxy;

  PolkitAuthority *authority;

  gboolean is_registered;

  PolkitAgentAuthenticationAgentBeginFunc begin_func;
  PolkitAgentAuthenticationAgentCancelFunc cancel_func;
  gpointer user_data;
};

struct _PolkitAgentAuthenticationAgentClass
{
  GObjectClass parent_class;

};

static void authentication_agent_iface_init (_PolkitAgentAuthenticationAgentIface *agent_iface);

G_DEFINE_TYPE_WITH_CODE (PolkitAgentAuthenticationAgent, polkit_agent_authentication_agent, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (_POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT,
                                                authentication_agent_iface_init)
                         );

static gboolean
polkit_agent_authentication_agent_register (PolkitAgentAuthenticationAgent  *agent,
                                            GError                         **error)
{
  GError *local_error;
  gboolean ret;

  ret = FALSE;

  local_error = NULL;
  if (!polkit_authority_register_authentication_agent_sync (agent->authority,
                                                            "/org/freedesktop/PolicyKit1/AuthenticationAgent",
                                                            NULL,
                                                            &local_error))
    {
      g_warning ("Unable to register authentication agent: %s", local_error->message);
      g_propagate_error (error, local_error);
    }
  else
    {
      agent->is_registered = TRUE;
      ret = TRUE;
    }

  return ret;
}

static void
name_owner_notify (EggDBusObjectProxy *object_proxy,
                   GParamSpec *pspec,
                   gpointer user_data)
{
  PolkitAgentAuthenticationAgent *agent = POLKIT_AGENT_AUTHENTICATION_AGENT (user_data);
  gchar *owner;

  owner = egg_dbus_object_proxy_get_name_owner (agent->authority_proxy);

  if (owner == NULL)
    {
      g_printerr ("PolicyKit daemon disconnected from the bus.\n");

      if (agent->is_registered)
        g_printerr ("We are no longer a registered authentication agent.\n");

      agent->is_registered = FALSE;
    }
  else
    {
      /* only register if there is a name owner */
      if (!agent->is_registered)
        {
          GError *error;

          g_printerr ("PolicyKit daemon reconnected to bus.\n");
          g_printerr ("Attempting to re-register as an authentication agent.\n");

          error = NULL;
          if (polkit_agent_authentication_agent_register (agent, &error))
            {
              g_printerr ("We are now a registered authentication agent.\n");
            }
          else
            {
              g_printerr ("Failed to register as an authentication agent: %s\n", error->message);
              g_error_free (error);
            }
        }
    }

  g_free (owner);
}

static void
polkit_agent_authentication_agent_init (PolkitAgentAuthenticationAgent *agent)
{
  GError *error;

  agent->system_bus = egg_dbus_connection_get_for_bus (EGG_DBUS_BUS_TYPE_SYSTEM);

  egg_dbus_connection_register_interface (agent->system_bus,
                                          "/org/freedesktop/PolicyKit1/AuthenticationAgent",
                                          _POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT,
                                          G_OBJECT (agent),
                                          G_TYPE_INVALID);

  agent->authority = polkit_authority_get ();

  /* the only use of this proxy is to re-register with the polkit daemon
   * if it jumps off the bus and comes back (which is useful for debugging)
   */
  agent->authority_proxy = egg_dbus_connection_get_object_proxy (agent->system_bus,
                                                                 "org.freedesktop.PolicyKit1",
                                                                 "/org/freedesktop/PolicyKit1/Authority");

  g_signal_connect (agent->authority_proxy,
                    "notify::name-owner",
                    G_CALLBACK (name_owner_notify),
                    agent);

  error = NULL;
  if (!polkit_agent_authentication_agent_register (agent, &error))
    {
      g_printerr ("Failed to register as an authentication agent: %s\n", error->message);
      g_error_free (error);
    }
}

static void
polkit_agent_authentication_agent_finalize (GObject *object)
{
  PolkitAgentAuthenticationAgent *agent = POLKIT_AGENT_AUTHENTICATION_AGENT (object);
  GError *error;

  error = NULL;
  if (!polkit_authority_unregister_authentication_agent_sync (agent->authority,
                                                              "/org/freedesktop/PolicyKit1/AuthenticationAgent",
                                                              NULL,
                                                              &error))
    {
      g_warning ("Error unregistering authentication agent: %s", error->message);
      g_error_free (error);
    }

  g_object_unref (agent->authority);

  g_object_unref (agent->authority_proxy);

  g_object_unref (agent->system_bus);

  if (G_OBJECT_CLASS (polkit_agent_authentication_agent_parent_class)->finalize != NULL)
    G_OBJECT_CLASS (polkit_agent_authentication_agent_parent_class)->finalize (object);
}

static void
polkit_agent_authentication_agent_class_init (PolkitAgentAuthenticationAgentClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->finalize = polkit_agent_authentication_agent_finalize;
}

PolkitAgentAuthenticationAgent *
polkit_agent_authentication_agent_new (PolkitAgentAuthenticationAgentBeginFunc begin_func,
                                       PolkitAgentAuthenticationAgentCancelFunc cancel_func,
                                       gpointer user_data)
{
  PolkitAgentAuthenticationAgent *agent;

  agent = POLKIT_AGENT_AUTHENTICATION_AGENT (g_object_new (POLKIT_AGENT_TYPE_AUTHENTICATION_AGENT, NULL));

  agent->begin_func = begin_func;
  agent->cancel_func = cancel_func;
  agent->user_data = user_data;

  return agent;
}

static void
handle_begin_authentication (_PolkitAgentAuthenticationAgent *instance,
                             const gchar *action_id,
                             const gchar *cookie,
                             EggDBusArraySeq *identities,
                             EggDBusMethodInvocation *method_invocation)
{
  PolkitAgentAuthenticationAgent *agent = POLKIT_AGENT_AUTHENTICATION_AGENT (instance);
  GList *list;
  guint n;
  GError *error;

  list = NULL;
  for (n = 0; n < identities->size; n++)
    {
      _PolkitIdentity *real_identity = _POLKIT_IDENTITY (identities->data.v_ptr[n]);

      list = g_list_prepend (list, polkit_identity_new_for_real (real_identity));
    }

  list = g_list_reverse (list);

  error = NULL;

  agent->begin_func (agent,
                     action_id,
                     cookie,
                     list,
                     (gpointer) method_invocation);

  g_list_free (list);
}

void
polkit_agent_authentication_agent_finish (PolkitAgentAuthenticationAgent *agent,
                                          gpointer                        pending_call,
                                          GError                         *error)
{
  EggDBusMethodInvocation *method_invocation = EGG_DBUS_METHOD_INVOCATION (pending_call);

  if (error != NULL)
    {
      egg_dbus_method_invocation_return_gerror (method_invocation, error);
    }
  else
    {
      _polkit_agent_authentication_agent_handle_begin_authentication_finish (method_invocation);
    }
}


static void
handle_cancel_authentication (_PolkitAgentAuthenticationAgent *instance,
                              const gchar *cookie,
                              EggDBusMethodInvocation *method_invocation)
{
  PolkitAgentAuthenticationAgent *agent = POLKIT_AGENT_AUTHENTICATION_AGENT (instance);

  agent->cancel_func (agent,
                      cookie,
                      agent->user_data);

  _polkit_agent_authentication_agent_handle_cancel_authentication_finish (method_invocation);
}

static void
authentication_agent_iface_init (_PolkitAgentAuthenticationAgentIface *agent_iface)
{
  agent_iface->handle_begin_authentication = handle_begin_authentication;
  agent_iface->handle_cancel_authentication = handle_cancel_authentication;
}

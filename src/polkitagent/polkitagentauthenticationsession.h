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

#ifndef __POLKIT_AGENT_AUTHENTICATION_SESSION_H
#define __POLKIT_AGENT_AUTHENTICATION_SESSION_H

#include <polkit/polkit.h>
#include <polkitagent/polkitagenttypes.h>

G_BEGIN_DECLS

#define POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION          (polkit_agent_authentication_session_get_type())
#define POLKIT_AGENT_AUTHENTICATION_SESSION(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION, PolkitAgentAuthenticationSession))
#define POLKIT_AGENT_AUTHENTICATION_SESSION_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION, PolkitAgentAuthenticationSessionClass))
#define POLKIT_AGENT_AUTHENTICATION_SESSION_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION, PolkitAgentAuthenticationSessionClass))
#define POLKIT_AGENT_IS_AUTHENTICATION_SESSION(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION))
#define POLKIT_AGENT_IS_AUTHENTICATION_SESSION_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_AGENT_TYPE_AUTHENTICATION_SESSION))

/**
 * PolkitAgentAuthenticationSessionConversationPromptEchoOff:
 * @session: A #PolkitAgentAuthenticationSession.
 * @prompt: prompt passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_agent_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer needs to ask the user a secret and the UI should NOT echo what
 * the user types on the screen.
 *
 * Returns: the answer obtained from the user; must be allocated with
 * malloc(3) and will be freed by the #PolkitAgentAuthenticationSession class.
 **/
typedef char* (*PolkitAgentAuthenticationSessionConversationPromptEchoOff) (PolkitAgentAuthenticationSession *session,
                                                                       const gchar               *prompt,
                                                                       gpointer                   user_data);

/**
 * PolkitAgentAuthenticationSessionConversationPromptEchoOn:
 * @session: A #PolkitAgentAuthenticationSession.
 * @prompt: prompt passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_agent_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer needs to ask the user a secret and the UI should echo what
 * the user types on the screen.
 *
 * Returns: the answer obtained from the user; must be allocated with
 * malloc(3) and will be freed by the #PolkitAgentAuthenticationSession class.
 **/
typedef char* (*PolkitAgentAuthenticationSessionConversationPromptEchoOn) (PolkitAgentAuthenticationSession *session,
                                                                      const gchar               *prompt,
                                                                      gpointer                   user_data);

/**
 * PolkitAgentAuthenticationSessionConversationErrorMessage:
 * @session: A #PolkitAgentAuthenticationSession.
 * @error_message: error message passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_agent_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer produces an error message that should be displayed in the UI.
 **/
typedef void (*PolkitAgentAuthenticationSessionConversationErrorMessage) (PolkitAgentAuthenticationSession *session,
                                                                     const gchar               *error_message,
                                                                     gpointer                   user_data);

/**
 * PolkitAgentAuthenticationSessionConversationTextInfo:
 * @session: A #PolkitAgentAuthenticationSession.
 * @text_info: information passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_agent_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer produces an informational message that should be displayed in
 * the UI.
 **/
typedef void (*PolkitAgentAuthenticationSessionConversationTextInfo) (PolkitAgentAuthenticationSession *session,
                                                                 const gchar               *text_info,
                                                                 gpointer                   user_data);

/**
 * PolkitAgentAuthenticationSessionDone:
 * @session: A #PolkitAgentAuthenticationSession.
 * @gained_authorization: whether the authorization was obtained
 * @invalid_data: whether the input data was bogus (not including bad passwords)
 * @user_data: user data pointer as passed into polkit_agent_authorization_session_set_functions()
 *
 * This function is called when the granting process ends; either if
 * successful or if it was canceled using e.g. polkit_agent_authorization_session_cancel_auth().
 **/
typedef void (*PolkitAgentAuthenticationSessionDone) (PolkitAgentAuthenticationSession *session,
                                                 gboolean                   gained_authorization,
                                                 gboolean                   invalid_data,
                                                 gpointer                   user_data);


#if 0
typedef struct _PolkitAgentAuthenticationSession PolkitAgentAuthenticationSession;
#endif
typedef struct _PolkitAgentAuthenticationSessionClass PolkitAgentAuthenticationSessionClass;

GType                      polkit_agent_authentication_session_get_type         (void) G_GNUC_CONST;
PolkitAgentAuthenticationSession *polkit_agent_authentication_session_new              (PolkitIdentity            *identity,
                                                                         const gchar               *cookie);

/* TODO: would be much nicer to use signals here */
void                       polkit_agent_authentication_session_set_functions
                               (PolkitAgentAuthenticationSession *session,
                                PolkitAgentAuthenticationSessionConversationPromptEchoOff func_prompt_echo_off,
                                PolkitAgentAuthenticationSessionConversationPromptEchoOn func_prompt_echo_on,
                                PolkitAgentAuthenticationSessionConversationErrorMessage func_error_message,
                                PolkitAgentAuthenticationSessionConversationTextInfo func_text_info,
                                PolkitAgentAuthenticationSessionDone func_done,
                                void *user_data);

gboolean                   polkit_agent_authentication_session_initiate_auth    (PolkitAgentAuthenticationSession  *session);

void                       polkit_agent_authentication_session_cancel           (PolkitAgentAuthenticationSession  *session);

G_END_DECLS

#endif /* __POLKIT_AGENT_AUTHENTICATION_SESSION_H */

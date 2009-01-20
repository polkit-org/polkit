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

#ifndef __POLKIT_AUTHENTICATION_SESSION_H
#define __POLKIT_AUTHENTICATION_SESSION_H

#include <polkit/polkit.h>
#include <polkitagent/polkitagenttypes.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_AUTHENTICATION_SESSION          (polkit_authentication_session_get_type())
#define POLKIT_AUTHENTICATION_SESSION(o)            (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHENTICATION_SESSION, PolkitAuthenticationSession))
#define POLKIT_AUTHENTICATION_SESSION_CLASS(k)      (G_TYPE_CHECK_CLASS_CAST((k), POLKIT_TYPE_AUTHENTICATION_SESSION, PolkitAuthenticationSessionClass))
#define POLKIT_AUTHENTICATION_SESSION_GET_CLASS(o)  (G_TYPE_INSTANCE_GET_CLASS ((o), POLKIT_TYPE_AUTHENTICATION_SESSION, PolkitAuthenticationSessionClass))
#define POLKIT_IS_AUTHENTICATION_SESSION(o)         (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHENTICATION_SESSION))
#define POLKIT_IS_AUTHENTICATION_SESSION_CLASS(k)   (G_TYPE_CHECK_CLASS_TYPE ((k), POLKIT_TYPE_AUTHENTICATION_SESSION))

/**
 * PolkitAuthenticationSessionConversationPromptEchoOff:
 * @session: A #PolkitAuthenticationSession.
 * @prompt: prompt passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer needs to ask the user a secret and the UI should NOT echo what
 * the user types on the screen.
 *
 * Returns: the answer obtained from the user; must be allocated with
 * malloc(3) and will be freed by the #PolkitAuthenticationSession class.
 **/
typedef char* (*PolkitAuthenticationSessionConversationPromptEchoOff) (PolkitAuthenticationSession *session,
                                                                       const gchar               *prompt,
                                                                       gpointer                   user_data);

/**
 * PolkitAuthenticationSessionConversationPromptEchoOn:
 * @session: A #PolkitAuthenticationSession.
 * @prompt: prompt passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer needs to ask the user a secret and the UI should echo what
 * the user types on the screen.
 *
 * Returns: the answer obtained from the user; must be allocated with
 * malloc(3) and will be freed by the #PolkitAuthenticationSession class.
 **/
typedef char* (*PolkitAuthenticationSessionConversationPromptEchoOn) (PolkitAuthenticationSession *session,
                                                                      const gchar               *prompt,
                                                                      gpointer                   user_data);

/**
 * PolkitAuthenticationSessionConversationErrorMessage:
 * @session: A #PolkitAuthenticationSession.
 * @error_message: error message passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer produces an error message that should be displayed in the UI.
 **/
typedef void (*PolkitAuthenticationSessionConversationErrorMessage) (PolkitAuthenticationSession *session,
                                                                     const gchar               *error_message,
                                                                     gpointer                   user_data);

/**
 * PolkitAuthenticationSessionConversationTextInfo:
 * @session: A #PolkitAuthenticationSession.
 * @text_info: information passed by the authentication layer; do not free this string
 * @user_data: user data pointer as passed into polkit_authorization_session_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer produces an informational message that should be displayed in
 * the UI.
 **/
typedef void (*PolkitAuthenticationSessionConversationTextInfo) (PolkitAuthenticationSession *session,
                                                                 const gchar               *text_info,
                                                                 gpointer                   user_data);

/**
 * PolkitAuthenticationSessionDone:
 * @session: A #PolkitAuthenticationSession.
 * @gained_authorization: whether the authorization was obtained
 * @invalid_data: whether the input data was bogus (not including bad passwords)
 * @user_data: user data pointer as passed into polkit_authorization_session_set_functions()
 *
 * This function is called when the granting process ends; either if
 * successful or if it was canceled using e.g. polkit_authorization_session_cancel_auth().
 **/
typedef void (*PolkitAuthenticationSessionDone) (PolkitAuthenticationSession *session,
                                                 gboolean                   gained_authorization,
                                                 gboolean                   invalid_data,
                                                 gpointer                   user_data);


#if 0
typedef struct _PolkitAuthenticationSession PolkitAuthenticationSession;
#endif
typedef struct _PolkitAuthenticationSessionClass PolkitAuthenticationSessionClass;

GType                      polkit_authentication_session_get_type         (void) G_GNUC_CONST;
PolkitAuthenticationSession *polkit_authentication_session_new              (PolkitIdentity            *identity,
                                                                         const gchar               *cookie);

/* TODO: would be much nicer to use signals here */
void                       polkit_authentication_session_set_functions
                               (PolkitAuthenticationSession *session,
                                PolkitAuthenticationSessionConversationPromptEchoOff func_prompt_echo_off,
                                PolkitAuthenticationSessionConversationPromptEchoOn func_prompt_echo_on,
                                PolkitAuthenticationSessionConversationErrorMessage func_error_message,
                                PolkitAuthenticationSessionConversationTextInfo func_text_info,
                                PolkitAuthenticationSessionDone func_done,
                                void *user_data);

gboolean                   polkit_authentication_session_initiate_auth    (PolkitAuthenticationSession  *session);

void                       polkit_authentication_session_cancel           (PolkitAuthenticationSession  *session);

G_END_DECLS

#endif /* __POLKIT_AUTHENTICATION_SESSION_H */

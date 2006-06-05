/***************************************************************************
 *
 * libpolkit-grant.h : Wraps temporary grant methods on the PolicyKit daemon
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBPOLKIT_GRANT_H
#define LIBPOLKIT_GRANT_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <libpolkit/libpolkit.h>


struct LibPolKitGrantContext_s;
typedef struct LibPolKitGrantContext_s LibPolKitGrantContext;

/**
 * LibPolKitGrantQuestions:
 * @ctx: Context
 * @questions: NULL terminated series of pairs. Each pair represent one question.
 * @user_data: User data
 *
 * Callback when information is needed from the user in order to
 * authenticate.
 *
 * The first component of the each pair in the questions array denote
 * the question type. It can assume the values "PamPromptEchoOff"
 * (meaning prompt for answer but don't echo it on the screen as the
 * user types it), "PamPromptEchoOn" (meaning prompt for answer and
 * echo the answer on the screen as the user types it), "PamErrorMsg"
 * (display the message as an error message to the user) and
 * "PamTextInfo" (textual information to the user). The second
 * component in the pair is the actual question or information
 * (e.g. "Password:") and it should be shown to the user next to the
 * text input box.
 *
 * The callee should call libpolkit_grant_provide_answers with a
 * string array once it the answers have been obtained from the user.
 *
 */
typedef void         (*LibPolKitGrantQuestions)                   (LibPolKitGrantContext   *ctx, 
								   const char             **questions,
								   gpointer                 user_data);

/**
 * LibPolKitGrantComplete:
 * @obtained_privilege: Whether the user sucessfully authenticated
 * and was granted the privilege.
 * @reason_not_obtained: If the user did not obtain the privilege
 * this is the reason. May be NULL.
 * @user_data: User data
 *
 * Callback when authorization was complete or there was an error.
 *
 */
typedef void         (*LibPolKitGrantComplete)                    (LibPolKitGrantContext   *ctx, 
					                           gboolean                 obtained_privilege,
								   const char              *reason_not_obtained,
					                           gpointer                 user_data);


LibPolKitGrantContext* libpolkit_grant_new_context                (DBusGConnection         *dbus_g_connection,
								   const char              *user,
							           const char              *privilege,
							           const char              *resource,
							           gboolean                 restrict_to_dbus_connection,
								   gpointer                 user_data);

const char*            libpolkit_grant_get_user                   (LibPolKitGrantContext    *ctx);

const char*            libpolkit_grant_get_privilege              (LibPolKitGrantContext    *ctx);

const char*            libpolkit_grant_get_resource               (LibPolKitGrantContext    *ctx);

LibPolKitContext*      libpolkit_grant_get_libpolkit_context      (LibPolKitGrantContext   *ctx);

void                   libpolkit_grant_set_questions_handler      (LibPolKitGrantContext   *ctx,
							           LibPolKitGrantQuestions  questions_handler);

void                   libpolkit_grant_set_grant_complete_handler (LibPolKitGrantContext   *ctx,
							           LibPolKitGrantComplete   grant_complete_handler);

gboolean               libpolkit_grant_initiate_temporary_grant   (LibPolKitGrantContext    *ctx);

const char*            libpolkit_grant_get_user_for_auth          (LibPolKitGrantContext    *ctx);

const char*            libpolkit_grant_get_pam_service_for_auth   (LibPolKitGrantContext    *ctx);

void                   libpolkit_grant_provide_answers            (LibPolKitGrantContext    *ctx,
								   const char              **answers);

gboolean               libpolkit_grant_close                      (LibPolKitGrantContext    *ctx,
								   gboolean                  revoke_privilege);

void                   libpolkit_grant_free_context               (LibPolKitGrantContext    *ctx);


#endif /* LIBPOLKIT_GRANT_H */



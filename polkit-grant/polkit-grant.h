/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant.h : library for obtaining privileges
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
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

#ifndef POLKIT_GRANT_H
#define POLKIT_GRANT_H

#include <polkit/polkit.h>

struct PolKitGrant;
typedef struct PolKitGrant PolKitGrant;

/**
 * PolKitGrantType:
 * @polkit_grant: the grant object
 * @grant_type: the current type of what privilege to obtain
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * Type for callback function that describes to what extent the
 * privilege can be obtained; e.g. whether the user can keep it
 * (e.g. forever, for the session or not keep it at all).
 *
 * See also #PolKitGrantOverrideGrantType for discussion on the type
 * of user interfaces one should put up depending on the value of
 * @grant_type.
 **/
typedef void (*PolKitGrantType) (PolKitGrant *polkit_grant,
                                 PolKitResult grant_type,
                                 void *user_data);

/**
 * PolKitGrantConversationPromptEchoOff:
 * @polkit_grant: the grant object
 * @prompt: prompt passed by the authentication layer; do not free this string
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer needs to ask the user a secret and the UI should NOT echo what
 * the user types on the screen.
 *
 * Returns: the answer obtained from the user; must be allocated with
 * malloc(3) and will be freed by the #PolKitGrant class.
 **/
typedef char* (*PolKitGrantConversationPromptEchoOff) (PolKitGrant *polkit_grant,
                                                       const char *prompt,
                                                       void       *user_data);

/**
 * PolKitGrantConversationPromptEchoOn:
 * @polkit_grant: the grant object
 * @prompt: prompt passed by the authentication layer; do not free this string
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer needs to ask the user a secret and the UI should echo what
 * the user types on the screen.
 *
 * Returns: the answer obtained from the user; must be allocated with
 * malloc(3) and will be freed by the #PolKitGrant class.
 **/
typedef char* (*PolKitGrantConversationPromptEchoOn) (PolKitGrant *polkit_grant,
                                                      const char *prompt,
                                                      void       *user_data);

/**
 * PolKitGrantConversationErrorMessage:
 * @polkit_grant: the grant object
 * @error_message: error message passed by the authentication layer; do not free this string
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer produces an error message that should be displayed in the UI.
 **/
typedef void (*PolKitGrantConversationErrorMessage) (PolKitGrant *polkit_grant,
                                                     const char *error_message,
                                                     void       *user_data);

/**
 * PolKitGrantConversationTextInfo:
 * @polkit_grant: the grant object
 * @text_info: information passed by the authentication layer; do not free this string
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * Type for callback function that is invoked when the authentication
 * layer produces an informational message that should be displayed in
 * the UI.
 **/
typedef void (*PolKitGrantConversationTextInfo) (PolKitGrant *polkit_grant,
                                                 const char *text_info,
                                                 void       *user_data);

/**
 * PolKitGrantOverrideGrantType:
 * @polkit_grant: the grant object
 * @grant_type: the current type of what privilege to obtain; this is
 * the same value as passed to the callback of type #PolKitGrantType.
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * Type for callback function that enables the UI to request a lesser
 * privilege than is obtainable. This callback is invoked when the
 * user have successfully authenticated but before the privilege is
 * granted.
 *
 * Basically, this callback enables a program to provide an user
 * interface like this:
 *
 * <programlisting>
 * +------------------------------------------------------------+
 * | You need to authenticate to access the volume 'Frobnicator |
 * | Adventures Vol 2'                                          |
 * |                                                            |
 * | Password: [_________________]                              |
 * |                                                            |
 * [ [x] Remember this decision                                 |
 * |   [ ] for this session                                     |
 * |   [*] for this and future sessions                         |
 * |                                                            |
 * |                                    [Cancel] [Authenticate] |
 * +------------------------------------------------------------+
 * </programlisting>
 *
 * This dialog assumes that @grant_type passed was
 * #POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_ALWAYS. By ticking the
 * check boxes in the dialog, the user can override this to either
 * #POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION or
 * #POLKIT_RESULT_ONLY_VIA_SELF_AUTH. Thus, the user can
 * voluntarily choose to obtain a lesser privilege.
 *
 * Another example, would be that the @grant_type passed was
 * #POLKIT_RESULT_ONLY_VIA_SELF_AUTH_KEEP_SESSION. Then the dialog
 * should look like this:
 *
 * <programlisting>
 * +------------------------------------------------------------+
 * | You need to authenticate to access the volume 'Frobnicator |
 * | Adventures Vol 2'                                          |
 * |                                                            |
 * | Password: [_________________]                              |
 * |                                                            |
 * [ [x] Remember this decision for the rest of the session     |
 * |                                                            |
 * |                                    [Cancel] [Authenticate] |
 * +------------------------------------------------------------+
 * </programlisting>
 *
 * Finally, if the @grant_type value passed is
 * e.g. #POLKIT_RESULT_ONLY_VIA_SELF_AUTH, there are no options to
 * click.:
 *
 * <programlisting>
 * +------------------------------------------------------------+
 * | You need to authenticate to access the volume 'Frobnicator |
 * | Adventures Vol 2'                                          |
 * |                                                            |
 * | Password: [_________________]                              |
 * |                                                            |
 * |                                    [Cancel] [Authenticate] |
 * +------------------------------------------------------------+
 * </programlisting>
 *
 * Of course, these examples also applies to
 * #POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH and friends.
 *
 * Returns: the desired type of what privilege to obtain; note that it
 * won't work asking for more privileges than what @grant_type
 * specifies; the passed value is properly checked in the secure
 * setgid granting helper mentioned in
 * polkit_grant_initiate_auth().
 **/
typedef PolKitResult (*PolKitGrantOverrideGrantType) (PolKitGrant *polkit_grant,
                                                      PolKitResult grant_type,
                                                      void *user_data);

/**
 * PolKitGrantDone:
 * @polkit_grant: the grant object
 * @gained_privilege: whether the privilege was obtained
 * @invalid_data: whether the input data was bogus (not including bad passwords)
 * @user_data: user data pointed as passed into polkit_grant_set_functions()
 *
 * This function is called when the granting process ends; either if
 * successful or if it was canceled using
 * e.g. polkit_grant_cancel_auth().
 **/
typedef void (*PolKitGrantDone) (PolKitGrant *polkit_grant,
                                 polkit_bool_t gained_privilege,
                                 polkit_bool_t invalid_data,
                                 void *user_data);

/**
 * PolKitGrantAddChildWatch:
 * @polkit_grant: the grant object
 * @pid: the child pid to watch
 *
 * Type for function supplied by the application to integrate a watch
 * on a child process into the applications main loop. The
 * application must call polkit_grant_child_func() when the
 * child dies
 *
 * For glib mainloop, the function will typically look like this:
 *
 * <programlisting>
 * static void
 * child_watch_func (GPid pid,
 *                   gint status,
 *                   gpointer user_data)
 * {
 *         PolKitGrant *polkit_grant = user_data;
 *         polkit_grant_child_func (polkit_grant, pid, WEXITSTATUS (status));
 * }
 * 
 * static int 
 * add_child_watch (PolKitGrant *polkit_grant, pid_t pid)
 * {
 *         return g_child_watch_add (pid, child_watch_func, polkit_grant);
 * }
 * </programlisting>
 *
 * Returns: 0 if the watch couldn't be set up; otherwise an unique
 * identifier for the watch.
 **/
typedef int (*PolKitGrantAddChildWatch) (PolKitGrant *polkit_grant,
                                         pid_t pid);

/**
 * PolKitGrantAddIOWatch:
 * @polkit_grant: the grant object
 * @fd: the file descriptor to watch
 *
 * Type for function supplied by the application to integrate a watch
 * on a file descriptor into the applications main loop. The
 * application must call polkit_grant_io_func() when there is data
 * to read from the file descriptor.
 *
 * For glib mainloop, the function will typically look like this:
 *
 * <programlisting>
 * static gboolean
 * io_watch_have_data (GIOChannel *channel, GIOCondition condition, gpointer user_data)
 * {
 *         int fd;
 *         PolKitGrant *polkit_grant = user_data;
 *         fd = g_io_channel_unix_get_fd (channel);
 *         polkit_grant_io_func (polkit_grant, fd);
 *         return TRUE;
 * }
 * 
 * static int 
 * add_io_watch (PolKitGrant *polkit_grant, int fd)
 * {
 *         guint id = 0;
 *         GIOChannel *channel;
 *         channel = g_io_channel_unix_new (fd);
 *         if (channel == NULL)
 *                 goto out;
 *         id = g_io_add_watch (channel, G_IO_IN, io_watch_have_data, polkit_grant);
 *         if (id == 0) {
 *                 g_io_channel_unref (channel);
 *                 goto out;
 *         }
 *         g_io_channel_unref (channel);
 * out:
 *         return id;
 * }
 * </programlisting>
 *
 * Returns: 0 if the watch couldn't be set up; otherwise an unique
 * identifier for the watch.
 **/
typedef int (*PolKitGrantAddIOWatch) (PolKitGrant *polkit_grant,
                                      int fd);

/**
 * PolKitGrantRemoveWatch:
 * @polkit_grant: the grant object
 * @watch_id: the id obtained from using the supplied function
 * of type #PolKitGrantAddIOWatch or #PolKitGrantAddChildWatch.
 *
 * Type for function supplied by the application to remove a watch set
 * up via the supplied function of type #PolKitGrantAddIOWatch or type
 * #PolKitGrantAddChildWatch.
 *
 * For glib mainloop, the function will typically look like this:
 *
 * <programlisting>
 * static void 
 * remove_watch (PolKitGrant *polkit_auth, int watch_id)
 * {
 *         g_source_remove (watch_id);
 * }
 * </programlisting>
 *
 **/
typedef void (*PolKitGrantRemoveWatch) (PolKitGrant *polkit_grant,
                                        int watch_id);

PolKitGrant  *polkit_grant_new           (void);
PolKitGrant  *polkit_grant_ref           (PolKitGrant *polkit_grant);
void          polkit_grant_unref         (PolKitGrant *polkit_grant);
void          polkit_grant_set_functions (PolKitGrant *polkit_grant,
                                          PolKitGrantAddIOWatch func_add_io_watch,
                                          PolKitGrantAddChildWatch func_add_child_watch,
                                          PolKitGrantRemoveWatch func_remove_watch,
                                          PolKitGrantType func_type,
                                          PolKitGrantConversationPromptEchoOff func_prompt_echo_off,
                                          PolKitGrantConversationPromptEchoOn func_prompt_echo_on,
                                          PolKitGrantConversationErrorMessage func_error_message,
                                          PolKitGrantConversationTextInfo func_text_info,
                                          PolKitGrantOverrideGrantType func_override_grant_type,
                                          PolKitGrantDone func_done,
                                          void *user_data);

polkit_bool_t polkit_grant_initiate_auth (PolKitGrant  *polkit_grant,
                                          PolKitAction *action,
                                          PolKitCaller *caller);

void          polkit_grant_cancel_auth   (PolKitGrant *polkit_grant);

void          polkit_grant_io_func       (PolKitGrant *polkit_grant, int fd);
void          polkit_grant_child_func    (PolKitGrant *polkit_grant, pid_t pid, int exit_code);


#endif /* POLKIT_GRANT_H */



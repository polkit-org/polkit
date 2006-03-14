/***************************************************************************
 * CVSID: $Id$
 *
 * polkit-session.c : Session object
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <security/pam_appl.h>

#include "polkit-session.h"

enum
{
	AUTH_STATE_NOT_STARTED,
	AUTH_STATE_IN_PROGRESS,
	AUTH_STATE_HAVE_QUESTIONS,
	AUTH_STATE_NEED_ANSWERS,
	AUTH_STATE_DONE
};

struct PolicyKitSessionPrivate
{
	int session_number;
	DBusGConnection *connection;
	DBusGProxy *proxy;
	PolicyKitManager *manager;

	char *auth_as_user;
	char *auth_with_pam_service;

	uid_t calling_uid;
	pid_t calling_pid;
	char *calling_dbus_name;

	uid_t grant_to_uid;
	char *grant_privilege;
	char *grant_resource;
	pid_t grant_pid_restriction;

	gboolean have_granted_temp_privileges;

	int auth_state;
	gboolean is_authenticated;
	char *auth_denied_reason;
	GSList *auth_questions;

	GPid child_pid;
	GIOChannel *pam_channel;
	GIOChannel *pam_channel_write;
};

enum
{
	HAVE_QUESTIONS,
	AUTHENTICATION_DONE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE(PolicyKitSession, polkit_session, G_TYPE_OBJECT)

static GObjectClass *parent_class = NULL;

static void
polkit_session_init (PolicyKitSession *session)
{
	session->priv = g_new0 (PolicyKitSessionPrivate, 1);
	session->priv->session_number = 42;
	session->priv->is_authenticated = FALSE;
	session->priv->auth_state = AUTH_STATE_NOT_STARTED;
}

static void
polkit_session_finalize (PolicyKitSession *session)
{
	g_io_channel_unref (session->priv->pam_channel);
	g_io_channel_unref (session->priv->pam_channel_write);
	dbus_g_connection_unref (session->priv->connection);

	g_free (session->priv->auth_as_user);
	g_free (session->priv->auth_with_pam_service);

	g_free (session->priv->calling_dbus_name);

	g_free (session->priv->grant_privilege);
	g_free (session->priv->grant_resource);

	g_free (session->priv->auth_denied_reason);
	if (session->priv->auth_questions != NULL) {
		//g_slist_foreach (session->priv->auth_questions, (GFunc) g_free, NULL);
		//g_free (session->priv->auth_questions);
	}
	g_free (session->priv);

	G_OBJECT_CLASS (parent_class)->finalize (G_OBJECT (session));
}

static void
polkit_session_class_init (PolicyKitSessionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	signals[HAVE_QUESTIONS] =
		g_signal_new ("have_questions",
			      G_OBJECT_CLASS_TYPE (klass),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
			      0,
			      NULL, NULL,
			      g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	signals[AUTHENTICATION_DONE] =
		g_signal_new ("authentication_done",
			      G_OBJECT_CLASS_TYPE (klass),
			      G_SIGNAL_RUN_LAST | G_SIGNAL_DETAILED,
			      0,
			      NULL, NULL,
			      g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);


	gobject_class->finalize = (GObjectFinalizeFunc) polkit_session_finalize;
	parent_class = g_type_class_peek_parent (klass);
}


GQuark
polkit_session_error_quark (void)
{
	static GQuark ret = 0;
	if (ret == 0)
		ret = g_quark_from_static_string ("PolkitSessionObjectErrorQuark");
	return ret;
}

#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
polkit_session_error_get_type (void)
{
	static GType etype = 0;
	
	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (POLKIT_SESSION_ERROR_AUTHENTICATION_IN_PROGRESS, "AuthenticationInProgress"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_AUTHENTICATION_ALREADY_INITIATED, "AuthenticationAlreadyInitiated"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_NO_QUESTIONS, "AuthenticationNoQuestions"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_AUTHENTICATION_WAS_NOT_DENIED, "AuthenticationWasNotDenied"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_NO_RESOURCES, "NoResources"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_AUTHENTICATION_NOT_DONE, "AuthenticationNotDone"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_AUTHENTICATION_FAILED, "AuthenticationFailed"),
			ENUM_ENTRY (POLKIT_SESSION_ERROR_NOT_INITIATOR, "NotInitiator"),
			{ 0, 0, 0 }
		};
		
		g_assert (POLKIT_SESSION_NUM_ERRORS == G_N_ELEMENTS (values) - 1);
		
		etype = g_enum_register_static ("PolkitSessionError", values);
	}
	
	return etype;
}


static gboolean
polkit_session_check_caller (PolicyKitSession      *session,
			     DBusGMethodInvocation *context)
{
	char *sender;
	gboolean same_caller;

	same_caller = FALSE;

	sender = dbus_g_method_get_sender (context);
	if (sender != NULL) {
		if (strcmp (session->priv->calling_dbus_name, sender) == 0) {
			same_caller = TRUE;
		}
	}
			      
	if (!same_caller) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_NOT_INITIATOR,
							 "Only the session initiator can invoke methods on this interface. This incident will be reported."));
		/* TODO: log this attack to syslog */
	}

	return same_caller;
}

gboolean 
polkit_session_is_authenticated (PolicyKitSession      *session, 
				 DBusGMethodInvocation *context)
{
	/*g_debug ("is_authenticated");*/

	if (!polkit_session_check_caller (session, context))
		return FALSE;

	if (session->priv->auth_state != AUTH_STATE_DONE) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_IN_PROGRESS,
							 "This method cannot be invoked before the AuthenticationDone signal is emitted."));
		return FALSE;
	}

	dbus_g_method_return (context, session->priv->is_authenticated);
	return TRUE;
}

gboolean
polkit_session_get_auth_denied_reason (PolicyKitSession      *session, 
				       DBusGMethodInvocation *context)
{
	/*g_debug ("get_auth_denied_reason");*/

	if (!polkit_session_check_caller (session, context))
		return FALSE;

	if (session->priv->auth_state != AUTH_STATE_DONE) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_IN_PROGRESS,
							 "This method cannot be invoked before the AuthenticationDone signal is emitted."));
		return FALSE;
	}

	if (session->priv->is_authenticated) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_WAS_NOT_DENIED,
							 "The authentication was not denied."));
		return FALSE;
	}

	dbus_g_method_return (context, session->priv->auth_denied_reason);
	return TRUE;
}


/*
 * Interaction diagram
 * -------------------
 *
 *   some app                                                    polkitd
 *   ========                                                    =======
 *
 *      -> manager.InitiatePrivilegeGrant(user, privilege, resource) ->
 *                     <- Returns session object <-
 *
 *                   -> session.GetAuthDetails() ->
 *      <- Returns {<username we auth as>, <service_name used> ...} <-   # can we include what pam module? prolly not
 *
 *                     -> session.InitiateAuth() ->
 *                         <- Returns TRUE <-
 *               
 *                                                                       # app now waits for the AuthenticationDone()
 *                                                                       # or HaveQuestions() signals
 *                                .....
 *               
 *                      <- signal: HaveQuestions() <-
 *
 *                       -> session.GetQuestions() ->
 *                 <- Returns {question_1, question_2, ...} <-
 *
 *           -> session.ProvideAnswers({answer_1, answer_2, ...}) ->
 *                         <- Returns TRUE <-
 *
 *                                .....
 *
 *                 <- signal: AuthenticationDone() <-
 *               
 *                                .....
 *
 *                    -> session.IsAuthenticated() ->
 *                      <- Returns TRUE or FALSE <-
 *                                                                       
 *                                .....
 *
 *                    -> session.GetAuthFailureReason() ->               # Only if IsAuthenticated() returns FALSE
 *                     <- Returns <reason as string> <-
 *
 *                                .....
 *
 * Assume now IsAuthenticated() returned TRUE. There are a few different
 * scenarios.
 *
 *
 * SCENARIO 1: App needs the privilege only temporarily; e.g. not persistent 
 *             across reboots. The app may even restrict users of the privilege
 *             to his own process id. The app may ask for the privilege to
 *             not be revoked when it ends the session - if the app should
 *             disconnect from the bus before session.Close() the privilege
 *             is revoked though.
 *
 *             Example: gnome-mount needs privs to do work, restricts the
 *                      privs to it's own PID and asks for revocation when
 *                      it's done with it's work.
 *
 *             Example: g-d-m temporarily gives the privilege 'local-console-user'
 *                      when a new desktop session starts. It manually revokes
 *                      this when the session ends.
 *
 *      -> session.GrantPrivilegeTemporary(bool restrictToCallersPID) -> # add uid, pid of client to the 
 *                          <- Returns TRUE <-                           # temp_allow_list
 *
 *                                .....
 *
 *        (the app is now doing something useful with the privilege obtained)
 *
 *                                .....
 *
 *                 -> session.Close(bool doNotRevokePrivilege) ->                           
 *                         <- Returns TRUE <-                            # Remove uid, pid of client from the
 *                                                                       # temp_allow_list IFF revokePrivile is true
 */

typedef struct {
	int fd;
	int fdread;
} ConversationData;


/* TODO: is this a secure way of clearing memory? */
static void *
safe_memset (void *buf, int c, size_t len)
{ 
	return memset (buf, c, len);
}


static int
my_conversation (int n,
		 const struct pam_message **msg,
		 struct pam_response **resp,
		 void *data)
{
	GString *str;
	ConversationData *cd = (ConversationData *) data;
	struct pam_response *aresp;
	int i;
	int j;
	int num_real_questions = 0;
	int strl;
	char *cstr;
	int num_bytes_read;
	char *p;
	char readbuf[1024];
	char **answers = NULL;
	int num_answers;

	/*g_debug ("in my_conv");*/

	if (n <= 0 || n > PAM_MAX_NUM_MSG) {
		return PAM_CONV_ERR;
	}

	if ((aresp = calloc (n, sizeof (struct pam_response))) == NULL) {
		return PAM_BUF_ERR;
	}

	str = g_string_new ("Q");

	for (i = 0; i < n; ++i) {
		g_string_append_c (str, '\0');
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			g_string_append (str, "PamPromptEchoOff");
			num_real_questions++;
			break;
		case PAM_PROMPT_ECHO_ON:
			g_string_append (str, "PamPromptEchoOn");
			num_real_questions++;
			break;
		case PAM_ERROR_MSG:
			g_string_append (str, "PamErrorMsg");
			break;
		case PAM_TEXT_INFO:
			g_string_append (str, "PamTextInfo");
			break;

		default:
			/* TODO */
			break;
		}
		g_string_append_c (str, '\0');
		g_string_append_printf (str, "%s", msg[i]->msg);
	}

	strl = str->len;
	cstr = g_string_free (str, FALSE);
	/*g_debug ("strlen = %d", strl);*/
	write (cd->fd, (void *) cstr, (size_t) strl);
	g_free (cstr);

	answers = g_new0 (char *, num_real_questions + 1);

	/* now wait for parent to write answers */
	num_bytes_read = read (cd->fdread, readbuf, sizeof (readbuf));
	/*g_debug ("actually read = %d", num_bytes_read);*/
	p = readbuf;
	num_answers = 0;
	do {
		if (num_answers > num_real_questions) {
			g_warning ("num_answers > num_real_questions");
			goto error;
		}

		answers [num_answers++] = g_strdup (p);
		/*g_debug ("answer -> '%s'", p);*/
		
		p = p + strlen(p) + 1;
		
	} while (p < readbuf + num_bytes_read);
	answers[num_answers] = NULL;

	if (num_answers != num_real_questions) {
		g_warning ("num_answers != num_real_questions");
		goto error;
	}

	/*g_debug ("giving answers back to PAM");*/

	j = 0;
	for (i = 0; i < n; ++i) {
		aresp[i].resp_retcode = 0;
		aresp[i].resp = NULL;

		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF: /* explicit fallthrough */
		case PAM_PROMPT_ECHO_ON:
			aresp[i].resp = strdup (answers[j++]);
			break;

		default:
			/* explicitly left blank */
			break;
		}
	}

	/* zero out the secrets */
	safe_memset (readbuf, 0, sizeof (readbuf));
	if (answers != NULL) {
		for (i = 0; answers[i] != NULL; i++) {
			safe_memset (answers[i], 0, strlen (answers[i]));
		}
		g_strfreev (answers);
	}

	*resp = aresp;
	return PAM_SUCCESS;

error:
	/* zero out the secrets */
	safe_memset (readbuf, 0, sizeof (readbuf));
	if (answers != NULL) {
		for (i = 0; answers[i] != NULL; i++) {
			safe_memset (answers[i], 0, strlen (answers[i]));
		}
		g_strfreev (answers);
	}

	/* prepare reply to PAM */
        for (i = 0; i < n; ++i) {
                if (aresp[i].resp != NULL) {
                        safe_memset (aresp[i].resp, 0, strlen(aresp[i].resp));
                        free (aresp[i].resp);
                }
        }
        safe_memset (aresp, 0, n * sizeof (struct pam_response));
	*resp = NULL;

	return PAM_CONV_ERR;
}

static void
write_back_to_parent (int fd, char code, const char *message)
{
	GString *str;
	gsize strl;
	char *cstr;
	
	str = g_string_new ("");
	g_string_append_c (str, code);
	g_string_append_c (str, '\0');

	if (message != NULL) {
		g_string_append (str, message);
		g_string_append_c (str, '\0');
	}

	strl = str->len;
	cstr = g_string_free (str, FALSE);
	write (fd, cstr, strl);
	g_free (cstr);
}

static void
do_pam_auth (int fd, int fdread, const PolicyKitSessionPrivate *priv)
{
	int rc;
	struct pam_conv pam_conversation;
	pam_handle_t *pam_h;
	ConversationData d;
	char *authed_user;

	/*g_debug ("in %s", __FUNCTION__);*/

	pam_conversation.conv        = my_conversation;
	pam_conversation.appdata_ptr = (void *) &d;
	d.fd = fd;
	d.fdread = fdread;

	rc = pam_start (priv->auth_with_pam_service,
			priv->auth_as_user, 
			&pam_conversation,
			&pam_h);
	if (rc != PAM_SUCCESS) {
		g_warning ("pam_start failed: %s", pam_strerror (pam_h, rc));
		write_back_to_parent (fd, 'F', pam_strerror (pam_h, rc));
		goto out;
	}


	/*g_debug ("invoking pam_authenticate");*/

	/* is user really user? */
	rc = pam_authenticate (pam_h, 0);
	if (rc != PAM_SUCCESS) {
		g_warning ("pam_authenticated failed: %s", pam_strerror (pam_h, rc));
		write_back_to_parent (fd, 'N', pam_strerror (pam_h, rc));
		goto out;
	}

	/*g_debug ("invoking pam_acct_mgmt");*/

	/* permitted access? */
	rc = pam_acct_mgmt (pam_h, 0);
	if (rc != PAM_SUCCESS) {
		g_warning ("pam_acct_mgmt failed: %s", pam_strerror (pam_h, rc));
		write_back_to_parent (fd, 'N', pam_strerror (pam_h, rc));
		goto out;
	}

	/*g_debug ("checking we authed the right user");*/

	rc = pam_get_item (pam_h, PAM_USER, (const void **) &authed_user);
	if (rc != PAM_SUCCESS) {
		g_warning ("pam_get_item failed: %s", pam_strerror (pam_h, rc));
		write_back_to_parent (fd, 'N', pam_strerror (pam_h, rc));
		goto out;
	}

	/*g_debug ("Authed user '%s'", authed_user);*/

	if (strcmp (authed_user, priv->auth_as_user) != 0) {
		char *err;
		err = g_strdup_printf ("Tried to auth user '%s' but we got auth for user '%s' instead",
				       priv->auth_as_user, authed_user);
		g_warning (err);
		write_back_to_parent (fd, 'N', err);
		g_free (err);
		goto out;
	}

	/*g_debug ("user authenticated, exiting");*/
	write_back_to_parent (fd, 'S', NULL);

out:
	exit (0);
}

static gboolean
data_from_pam (GIOChannel *source,
	       GIOCondition condition,
	       gpointer data)
{
	PolicyKitSession *session = POLKIT_SESSION (data);

	if (condition & G_IO_IN) {
		char buf[1024];
		gsize num_bytes_read;

		/*g_debug ("in %s - data", __FUNCTION__);*/

		g_io_channel_read (source,
				   buf,
				   sizeof (buf) - 1,
				   &num_bytes_read);
		/*g_debug ("read %d bytes, first one is '%c' = %d", num_bytes_read, buf[0], buf[0]);*/
		buf[num_bytes_read] = '\0';

		switch (buf[0]) {
		case 'F':
			g_warning ("PAM failed: '%s'", buf + 2);
			session->priv->auth_denied_reason = g_strdup (buf + 2);
			session->priv->auth_state = AUTH_STATE_DONE;
			g_signal_emit (session, signals[AUTHENTICATION_DONE], 0);
			break;

		case 'N':
			g_warning ("Not authenticated: '%s'", buf + 2);
			session->priv->auth_denied_reason = g_strdup (buf + 2);
			session->priv->auth_state = AUTH_STATE_DONE;
			g_signal_emit (session, signals[AUTHENTICATION_DONE], 0);
			break;

		case 'S':
			/*g_debug ("Success, user authenticated");*/
			session->priv->is_authenticated = TRUE;
			session->priv->auth_state = AUTH_STATE_DONE;
			g_signal_emit (session, signals[AUTHENTICATION_DONE], 0);
			break;

		case 'Q':
			g_slist_foreach (session->priv->auth_questions, (GFunc) g_free, NULL);
			g_slist_free (session->priv->auth_questions);
			session->priv->auth_questions = NULL;

			char *p = buf + 2;
			do {
				session->priv->auth_questions = g_slist_append (session->priv->auth_questions,
										g_strdup (p));
				/*g_debug ("p -> '%s'", p);*/
				p = p + strlen(p) + 1;

			} while (p < buf + num_bytes_read);

			/*g_debug ("Put %d questions on list", g_slist_length (session->priv->auth_questions));*/

			if ((g_slist_length (session->priv->auth_questions) & 1) != 0) {
				g_warning ("Uneven number of question items from PAM; aborting conversation");
				kill (session->priv->child_pid, SIGTERM);
				session->priv->auth_state = AUTH_STATE_DONE;
				session->priv->auth_denied_reason = g_strdup ("Unexpected internal PAM error");
				g_signal_emit (session, signals[AUTHENTICATION_DONE], 0);
			} else {
				session->priv->auth_state = AUTH_STATE_HAVE_QUESTIONS;
				g_signal_emit (session, signals[HAVE_QUESTIONS], 0);
			}
			break;

		default:
			/* left intentionally blank */
			break;
		}

	}


	if (condition & G_IO_HUP) {
		/*g_debug ("in %s - hangup", __FUNCTION__);*/
		if (session->priv->child_pid != 0) {
			int status;
			/*g_debug ("  reaping child with pid %d", session->priv->child_pid);*/
			session->priv->child_pid = 0;
			waitpid (session->priv->child_pid, &status, 0);
		}
		/* remove the source */
		return FALSE;
	}

	return TRUE;
}

gboolean
polkit_session_get_auth_details (PolicyKitSession      *session, 
				 DBusGMethodInvocation *context)
{
	if (!polkit_session_check_caller (session, context))
		return FALSE;

	if (session->priv->auth_state != AUTH_STATE_NOT_STARTED) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_ALREADY_INITIATED,
							 "This method cannot be invoked after InitiateAuth() is invoked."));
		return FALSE;
	}
	
	dbus_g_method_return (context, 
			      g_strdup (session->priv->auth_as_user),
			      g_strdup (session->priv->auth_with_pam_service));
	return TRUE;
}

gboolean 
polkit_session_initiate_auth (PolicyKitSession      *session, 
			      DBusGMethodInvocation *context)
{
	int fds[2];
	int fdsb[2];
	pid_t pid;

	if (!polkit_session_check_caller (session, context))
		return FALSE;

	if (session->priv->auth_state != AUTH_STATE_NOT_STARTED) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_ALREADY_INITIATED,
							 "Authentication already initiated."));
		return FALSE;
	}

	/*g_debug ("in %s", __FUNCTION__);*/

	/* pipe for parent reading from child */
	if (pipe(fds) != 0) {
		g_warning ("pipe() failed: %s", strerror (errno));
		goto fail;
	}

	/* pipe for parent writing to child */
	if (pipe(fdsb) != 0) {
		g_warning ("pipe() failed: %s", strerror (errno));
		goto fail;
	}
	
	switch (pid = fork()) {
	case -1:
		g_warning ("fork() failed: %s", strerror (errno));
		goto fail;
		
	case 0:
		/* child; close unused ends */
		close (fds[0]);
		close (fdsb[1]);

		do_pam_auth (fds[1], fdsb[0], session->priv);
		break;
		
	default:
		session->priv->auth_state = AUTH_STATE_IN_PROGRESS;

		/* parent; close unused ends */
		close (fds[1]);
		close (fdsb[0]);

		session->priv->child_pid = (GPid) pid;
		session->priv->pam_channel_write = g_io_channel_unix_new (fdsb[1]);
		session->priv->pam_channel = g_io_channel_unix_new (fds[0]);

		g_io_add_watch (session->priv->pam_channel, 
				G_IO_IN | G_IO_ERR | G_IO_HUP,
				data_from_pam,
				session);

		break;
	}

	dbus_g_method_return (context);
	return TRUE;

fail:
	dbus_g_method_return_error (context, 
				    g_error_new (POLKIT_SESSION_ERROR,
						 POLKIT_SESSION_ERROR_NO_RESOURCES,
						 "InitiateAuth() failed due to lack of resources. Try again later."));

	return FALSE;
}

gboolean
polkit_session_get_questions    (PolicyKitSession      *session, 
				 DBusGMethodInvocation *context)
{
	int n;
	GSList *i;
	char **questions;

	if (!polkit_session_check_caller (session, context))
		return FALSE;

	/*g_debug ("in %s", __FUNCTION__);*/

	if (session->priv->auth_state != AUTH_STATE_HAVE_QUESTIONS) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_NO_QUESTIONS,
							 "There are currently no questions available."));
		return FALSE;
	}

	session->priv->auth_state = AUTH_STATE_NEED_ANSWERS;

	questions = g_new0 (char *, g_slist_length (session->priv->auth_questions) + 1);
	for (i = session->priv->auth_questions, n = 0; i != NULL; i = g_slist_next (i)) {
		char *question = (char *) i->data;
		questions[n++] = g_strdup (question);
	}
	questions[n] = NULL;

	dbus_g_method_return (context, questions);
	return TRUE;
}

gboolean
polkit_session_provide_answers  (PolicyKitSession      *session, 
				 char                 **answers, 
				 DBusGMethodInvocation *context)
{
	int i;
	GString *str;
	char *cstr;
	gsize strl;
	gsize num_bytes_written;

	if (!polkit_session_check_caller (session, context))
		return FALSE;

	/*g_debug ("in %s", __FUNCTION__);*/

	if (session->priv->auth_state != AUTH_STATE_NEED_ANSWERS) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_NO_QUESTIONS,
							 "There are currently no questions pending answers."));
		return FALSE;
	}

	session->priv->auth_state = AUTH_STATE_IN_PROGRESS;

	str = g_string_new ("");
	for (i = 0; answers[i] != NULL; i++) {
		/*g_debug ("answer %d: %s", i, answers[i]);*/
		g_string_append (str, answers[i]);
		g_string_append_c (str, '\0');
	}
	strl = str->len;
	cstr = g_string_free (str, FALSE);
	g_io_channel_write (session->priv->pam_channel_write, cstr, strl, &num_bytes_written);
	g_free (cstr);

	/*g_debug ("wanted to write %d bytes, wrote %d bytes", strl, num_bytes_written);*/

	dbus_g_method_return (context);
	return TRUE;
}

gboolean
polkit_session_close (PolicyKitSession      *session, 
		      gboolean               do_not_revoke_privilege,
		      DBusGMethodInvocation *context)
{
	/*g_debug ("in %s", __FUNCTION__);*/

	if (!polkit_session_check_caller (session, context))
		return FALSE;

	if (!do_not_revoke_privilege && session->priv->have_granted_temp_privileges) {

		if (!polkit_manager_remove_temporary_privilege (session->priv->manager,
								session->priv->grant_to_uid,
								session->priv->grant_privilege,
								session->priv->grant_resource,
								session->priv->grant_pid_restriction)) {
			g_warning ("Could not remove tmp priv '%s' to uid %d for resource '%s' on pid %d",
				   session->priv->grant_privilege,
				   session->priv->grant_to_uid,
				   session->priv->grant_resource,
				   session->priv->grant_pid_restriction);
		}
	}

	g_object_unref (session);

	dbus_g_method_return (context);
	return TRUE;
}

gboolean 
polkit_session_grant_privilege_temporarily (PolicyKitSession      *session, 
					    gboolean               restrict_to_callers_pid,
					    DBusGMethodInvocation *context)
{
	if (!polkit_session_check_caller (session, context))
		return FALSE;

	if (session->priv->auth_state != AUTH_STATE_DONE) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_NOT_DONE,
							 "Authentication is not done."));
		return FALSE;
	}

	if (!session->priv->is_authenticated) {
		dbus_g_method_return_error (context, 
					    g_error_new (POLKIT_SESSION_ERROR,
							 POLKIT_SESSION_ERROR_AUTHENTICATION_FAILED,
							 "User failed authentication."));
		return FALSE;
	}

	session->priv->grant_pid_restriction = restrict_to_callers_pid ? session->priv->calling_pid : (pid_t) -1;
	if (!polkit_manager_add_temporary_privilege (session->priv->manager,
						     session->priv->grant_to_uid,
						     session->priv->grant_privilege,
						     session->priv->grant_resource,
						     session->priv->grant_pid_restriction)) {
		g_warning ("Could not add tmp priv '%s' to uid %d for resource '%s' on pid %d",
			   session->priv->grant_privilege,
			   session->priv->grant_to_uid,
			   session->priv->grant_resource,
			   session->priv->grant_pid_restriction);
	}

	session->priv->have_granted_temp_privileges = TRUE;

	dbus_g_method_return (context);
	return TRUE;
}

PolicyKitSession *
polkit_session_new (DBusGConnection    *connection, 
		    PolicyKitManager   *manager,
		    uid_t               calling_uid,
		    pid_t               calling_pid,
		    const char         *calling_dbus_name,
		    uid_t               uid,
		    const char         *privilege,
		    const char         *resource)
{
	char *objpath;
	PolicyKitSession *session;
	static int session_number_base = 0;

	session = POLKIT_SESSION (g_object_new (POLKIT_TYPE_SESSION, NULL));
	session->priv->connection = dbus_g_connection_ref (connection);
	session->priv->session_number = session_number_base++;
	session->priv->manager = manager;
	objpath = g_strdup_printf ("/org/freedesktop/PolicyKit/sessions/%d", session->priv->session_number);
	dbus_g_connection_register_g_object (connection, objpath, G_OBJECT (session));
	g_free (objpath);

	session->priv->calling_uid = calling_uid;
	session->priv->calling_pid = calling_pid;
	session->priv->calling_dbus_name = g_strdup (calling_dbus_name);

	session->priv->grant_to_uid = uid;
	session->priv->grant_privilege = g_strdup (privilege);
	session->priv->grant_resource = g_strdup (resource);

	/* TODO: look up auth_as_user, auth_with_pam_service from privilege configuration files */
	session->priv->auth_as_user = g_strdup ("root");
	session->priv->auth_with_pam_service = g_strdup ("policy-kit");

	return session;
}


void
polkit_session_initiator_disconnected (PolicyKitSession *session)
{
	/*g_debug ("initiator disconnected");*/

	if (session->priv->have_granted_temp_privileges) {
		if (!polkit_manager_remove_temporary_privilege (session->priv->manager,
								session->priv->grant_to_uid,
								session->priv->grant_privilege,
								session->priv->grant_resource,
								session->priv->grant_pid_restriction)) {
			g_warning ("Could not remove tmp priv '%s' to uid %d for resource '%s' on pid %d",
				   session->priv->grant_privilege,
				   session->priv->grant_to_uid,
				   session->priv->grant_resource,
				   session->priv->grant_pid_restriction);
		}
	}
}

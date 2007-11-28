/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-grant-helper-pam.c : setuid root pam grant helper for PolicyKit
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/

/* TODO: FIXME: XXX: this code needs security review before it can be released! */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <security/pam_appl.h>

/* Development aid: define PGH_DEBUG to get debugging output. Do _NOT_
 * enable this in production builds; it may leak passwords and other
 * sensitive information.
 */
#undef PGH_DEBUG
/* #define PGH_DEBUG */

static int conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data);

int 
main (int argc, char *argv[])
{
        int rc;
        char user_to_auth[256];
	struct pam_conv pam_conversation;
	pam_handle_t *pam_h;
        const void *authed_user;

        rc = 0;
        pam_h = NULL;

        /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
        if (clearenv () != 0)
                goto error;
        /* set a minimal environment */
        setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

        /* check that we are setuid root */
        if (geteuid () != 0) {
                fprintf (stderr, "polkit-grant-helper-pam: needs to be setuid root\n");
                goto error;
        }

        openlog ("polkit-grant-helper-pam", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

        /* check for correct invocation */
        if (argc != 1) {
                syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
                fprintf (stderr, "polkit-grant-helper-pam: wrong number of arguments. This incident has been logged.\n");
                goto error;
        }

        if (getuid () != 0) {
                /* check we're running with a non-tty stdin */
                if (isatty (STDIN_FILENO) != 0) {
                        syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
                        fprintf (stderr, "polkit-grant-helper-pam: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
                        goto error;
                }
        }

        /* get user to auth */
        if (fgets (user_to_auth, sizeof user_to_auth, stdin) == NULL)
                goto error;
        if (strlen (user_to_auth) > 0 && user_to_auth[strlen (user_to_auth) - 1] == '\n')
                user_to_auth[strlen (user_to_auth) - 1] = '\0';

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper-pam: user to auth is '%s'.\n", user_to_auth);
#endif /* PGH_DEBUG */

	pam_conversation.conv        = conversation_function;
	pam_conversation.appdata_ptr = NULL;

        /* start the pam stack */
	rc = pam_start ("polkit",
			user_to_auth, 
			&pam_conversation,
			&pam_h);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "polkit-grant-helper-pam: pam_start failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

        /* set the requesting user */
        rc = pam_set_item (pam_h, PAM_RUSER, user_to_auth);
        if (rc != PAM_SUCCESS) {
		fprintf (stderr, "polkit-grant-helper-pam: pam_set_item failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
        }

	/* is user really user? */
	rc = pam_authenticate (pam_h, 0);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "polkit-grant-helper-pam: pam_authenticated failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

	/* permitted access? */
	rc = pam_acct_mgmt (pam_h, 0);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "polkit-grant-helper-pam: pam_acct_mgmt failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

        /* did we auth the right user? */
	rc = pam_get_item (pam_h, PAM_USER, &authed_user);
	if (rc != PAM_SUCCESS) {
		fprintf (stderr, "polkit-grant-helper-pam: pam_get_item failed: %s\n", pam_strerror (pam_h, rc));
		goto error;
	}

	if (strcmp (authed_user, user_to_auth) != 0) {
                fprintf (stderr, "polkit-grant-helper-pam: Tried to auth user '%s' but we got auth for user '%s' instead",
                         user_to_auth, (const char *) authed_user);
		goto error;
	}

#ifdef PGH_DEBUG
        fprintf (stderr, "polkit-grant-helper-pam: successfully authenticated user '%s'.\n", user_to_auth);
#endif /* PGH_DEBUG */

        fprintf (stdout, "SUCCESS\n");
        fflush (stdout);

        pam_end (pam_h, rc);
        return 0;
error:
        if (pam_h != NULL)
                pam_end (pam_h, rc);

        fprintf (stdout, "FAILURE\n");
        fflush (stdout);
        return 1;
}

static int
conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
        struct pam_response *aresp;
        char buf[PAM_MAX_RESP_SIZE];
        int i;

        data = data;
        if (n <= 0 || n > PAM_MAX_NUM_MSG)
                return PAM_CONV_ERR;

        if ((aresp = calloc(n, sizeof *aresp)) == NULL)
                return PAM_BUF_ERR;

        for (i = 0; i < n; ++i) {
                aresp[i].resp_retcode = 0;
                aresp[i].resp = NULL;
                switch (msg[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                        fprintf (stdout, "PAM_PROMPT_ECHO_OFF ");
                        goto conv1;
                case PAM_PROMPT_ECHO_ON:
                        fprintf (stdout, "PAM_PROMPT_ECHO_ON ");
                conv1:
                        fputs (msg[i]->msg, stdout);
                        if (strlen (msg[i]->msg) > 0 &&
                            msg[i]->msg[strlen (msg[i]->msg) - 1] != '\n')
                                fputc ('\n', stdout);
                        fflush (stdout);

                        if (fgets (buf, sizeof buf, stdin) == NULL)
                                goto error;
                        if (strlen (buf) > 0 &&
                            buf[strlen (buf) - 1] == '\n')
                                buf[strlen (buf) - 1] = '\0';

                        aresp[i].resp = strdup (buf);
                        if (aresp[i].resp == NULL)
                                goto error;
                        break;

                case PAM_ERROR_MSG:
                        fprintf (stdout, "PAM_ERROR_MSG ");
                        goto conv2;

                case PAM_TEXT_INFO:
                        fprintf (stdout, "PAM_TEXT_INFO ");
                conv2:
                        fputs (msg[i]->msg, stdout);
                        if (strlen (msg[i]->msg) > 0 &&
                            msg[i]->msg[strlen (msg[i]->msg) - 1] != '\n')
                                fputc ('\n', stdout);
                        fflush (stdout);
                        break;
                default:
                        goto error;
                }
        }
        *resp = aresp;
        return PAM_SUCCESS;

error:
        for (i = 0; i < n; ++i) {
                if (aresp[i].resp != NULL) {
                        memset (aresp[i].resp, 0, strlen(aresp[i].resp));
                        free (aresp[i].resp);
                }
        }
        memset (aresp, 0, n * sizeof *aresp);
        *resp = NULL;
        return PAM_CONV_ERR;
}

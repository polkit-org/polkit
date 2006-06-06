/***************************************************************************
 * CVSID: $Id$
 *
 * pam-polkit-console.c : Maintain files in /var/run/polkit-console to
 *                        maintain a list of what users are logged in at
 *                        what console
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

#include <config.h>

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#ifdef HAVE_PAM_MODUTIL_H
#include <security/pam_modutil.h>
#endif
#ifdef HAVE_PAM_EXT_H
#include <security/pam_ext.h>
#endif

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

static int debug = 0;

static void
_pam_log (pam_handle_t *pamh, 
	  int err, 
	  int debug_noforce,
	  const char *format, ...)
{
	va_list args;

	if (debug_noforce && !debug) 
		return;

	va_start (args, format);
#ifdef HAVE_PAM_VSYSLOG
	pam_vsyslog (pamh, err, format, args);
#endif
	closelog ();
}

static void
_parse_module_args (pam_handle_t *pamh, 
		    int argc, 
		    const char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		const char *arg;

		arg = argv[i];
		if (strcmp (arg,"debug") == 0) {
			debug = 1;
		} else {
			_pam_log(pamh, LOG_ERR, FALSE,
				 "_parse_module_args: unknown option; %s", arg);
		}
	}
}

static int
_is_local_xconsole (const char *tty)
{
	int a, b;

	if (sscanf (tty, ":%d.%d", &a, &b) == 2)
		return TRUE;
	else if (sscanf (tty, ":%d", &a) == 1)
		return TRUE;
	else
		return FALSE;
}

static void
_poke_polkitd (pam_handle_t *pamh)
{
	char buf[80];

	/* This is a PAM module so we're loaded into the address space
	 * of some other process (e.g. gdm) - though it's tempting to
	 * use D-BUS to poke the PolicyKit daemon it may, just resort to
	 * using oldskool SIGUSR1 instead.
	 */

	FILE *f;
	f = fopen (POLKITD_PID_FILE, "r");
	if (f != NULL) {
		if (fgets (buf, sizeof (buf), f) != NULL && buf[0] != '\0' && buf[0] != '\n') {
			pid_t pid;
			char *p;
			
			pid = strtol (buf, &p, 10);
			if ((*p == '\0') || (*p == '\n'))
			{
				_pam_log (pamh, LOG_DEBUG, TRUE, 
					  "Sending SIGUSR1 to polkitd with pid %d to reload configuration", pid);
				kill (pid, SIGUSR1);
			}
		}
		fclose (f);
	}
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, 
		     int flags, 
		     int argc, 
		     const char **argv)
{
	return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh, 
		int flags, 
		int argc, 
		const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, 
		     int flags, 
		     int argc, 
		     const char **argv)
{
	const char *username = NULL;
	const char *user_prompt = NULL;
	const char *tty = NULL;
	char buf[256];

	_pam_log (pamh, LOG_ERR, TRUE, "pam_polkit_console open_session");
	_parse_module_args (pamh, argc, argv);
	if(pam_get_item (pamh, PAM_USER_PROMPT, (const void **) &user_prompt) != PAM_SUCCESS) {
		user_prompt = "user name: ";
	}
	username = NULL;
	pam_get_user (pamh, &username, user_prompt);
	if (username == NULL || strlen (username) == 0) {
		return PAM_SESSION_ERR;
	}

	pam_get_item(pamh, PAM_TTY, (const void**) &tty);
	if (tty == NULL || strlen (tty) == 0) {
		_pam_log(pamh, LOG_ERR, TRUE, "TTY not defined");
		return PAM_SESSION_ERR;
	}

	_pam_log (pamh, LOG_DEBUG, TRUE, "open_session for user '%s' @ TTY '%s'", username, tty);

	if (_is_local_xconsole (tty)) {
		if ((unsigned int) snprintf (buf, sizeof (buf), LOCKDIR "/%s_%s", tty, username) < sizeof (buf)) {
			int fd;

			fd = open (buf, O_RDWR|O_CREAT|O_EXCL, 0600);
			if (fd > 0) {
				_pam_log (pamh, LOG_DEBUG, TRUE, "open_session success; %s %s %s", 
					  username, tty, buf);
				close (fd);
				_poke_polkitd (pamh);
			}
		}
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, 
		      int flags, 
		      int argc, 
		      const char **argv)
{
	const char *username = NULL;
	const char *user_prompt = NULL;
	const char *tty = NULL;
	char buf[256];

	_pam_log (pamh, LOG_ERR, TRUE, "pam_polkit_console close_session");
	_parse_module_args (pamh, argc, argv);
	if (pam_get_item (pamh, PAM_USER_PROMPT, (const void **) &user_prompt) != PAM_SUCCESS) {
		user_prompt = "user name: ";
	}
	username = NULL;
	pam_get_user (pamh, &username, user_prompt);
	if (username == NULL || strlen (username) == 0) {
		return PAM_SESSION_ERR;
	}

	pam_get_item (pamh, PAM_TTY, (const void**) &tty);
	if (tty == NULL || strlen (tty) == 0) {
		_pam_log(pamh, LOG_ERR, TRUE, "TTY not defined");
		return PAM_SESSION_ERR;
	}

	_pam_log (pamh, LOG_DEBUG, TRUE, "close_session for user '%s' @ TTY '%s'", username, tty);

	if (_is_local_xconsole (tty)) {
		if ((unsigned int) snprintf (buf, sizeof (buf), LOCKDIR "/%s_%s", tty, username) < sizeof (buf)) {
			unlink (buf);
			_poke_polkitd (pamh);
		}
	}
	
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_polkit_console_modstruct = {
    "pam_polkit_console",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    pam_sm_open_session,
    pam_sm_close_session,
    NULL,
};

#endif

/* end of module definition */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file-validate.c : validate policy file
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdbool.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <libpolkit/libpolkit.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : polkit-policy-file-validate <policy-files>\n"
                 "        [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "Validates one or more PolicyKit policy file. Returns 0 if it validates.\n"
                 "If not, the program exits with a non-zero exit code.\n");
}

static bool
validate_file (const char *file)
{
        PolKitPolicyFile *priv_file;
        PolKitError *error;

        error = NULL;
        priv_file = libpolkit_policy_file_new (file, &error);
        if (priv_file == NULL) {
                printf ("%s did not validate: %s\n", file, polkit_error_get_error_message (error));
                polkit_error_free (error);
                return FALSE;
        }
        libpolkit_policy_file_unref (priv_file);
        return TRUE;
}

int
main (int argc, char *argv[])
{
        int n;

	if (argc <= 1) {
		usage (argc, argv);
                return 1;
	}

        for (n = 1; n < argc; n++) {
                if (strcmp (argv[n], "--help") == 0) {
                        usage (argc, argv);
                        return 0;
                }
                if (strcmp (argv[n], "--version") == 0) {
                        printf ("polkit-policy-file-validate " PACKAGE_VERSION "\n");
                        return 0;
                }

                if (!validate_file (argv[n])) {
                        return 1;
                }
	}

        return 0;
}

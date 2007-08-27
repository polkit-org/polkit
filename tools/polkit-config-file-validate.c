/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-config-file-validate.c : validate configuration file
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

#include <polkit/polkit.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : polkit-policy-file-validate [/path/to/config/file] [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "Validates if given file is a valid PolicyKit configuration file.\n"
                 "If no file is given, then /etc/PolicyKit/PolicyKit.conf is validated.\n"
                 "Returns 0 if the file is valid, otherwise a non-zero exit code is returned.\n");
}

int
main (int argc, char *argv[])
{
        int n;
        int ret;
        char *path;
        PolKitConfig *config;
        PolKitError *pk_error;

        ret = 1;

        path = NULL;
        for (n = 1; n < argc; n++) {
                if (strcmp (argv[n], "--help") == 0) {
                        usage (argc, argv);
                        ret = 0;
                        goto out;
                } else if (strcmp (argv[n], "--version") == 0) {
                        printf ("polkit-config-file-validate " PACKAGE_VERSION "\n");
                        ret = 0;
                        goto out;
                } else {
                        if (path != NULL) {
                                usage (argc, argv);
                                goto out;
                        }
                        path = argv[n];
                }
	}

        if (path == NULL)
                path = PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf";

        pk_error = NULL;
        config = polkit_config_new (path, &pk_error);
        if (config == NULL) {
                printf ("Configuration file is malformed: %s\n", polkit_error_get_error_message (pk_error));
                polkit_error_free (pk_error);
                goto out;
        }

        ret = 0;

out:
        return ret;
}

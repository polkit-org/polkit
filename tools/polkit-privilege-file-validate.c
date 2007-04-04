/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-privilege-file-validate.c : validate privilege file
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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <libpolkit/libpolkit-privilege-file.h>

static void
usage (int argc, char *argv[])
{
	fprintf (stderr,
                 "\n"
                 "usage : polkit-privilege-file-validate --file <privilege-file>\n"
                 "        [--version] [--help]\n");
	fprintf (stderr,
                 "\n"
                 "        --file           File to validate\n"
                 "        --version        Show version and exit\n"
                 "        --help           Show this information and exit\n"
                 "\n"
                 "Validates a PolicyKit privilege file. Returns 0 if it validates. If\n"
                 "not, the program exits with a non-zero exit code.\n");
}

int
main (int argc, char *argv[])
{
        char *file = NULL;
        gboolean is_version = FALSE;
        gboolean validated;
        PolKitPrivilegeFile *priv_file;
        GError *error = NULL;

        validated = FALSE;

	if (argc <= 1) {
		usage (argc, argv);
                goto out;
	}

	while (1) {
		int c;
		int option_index = 0;
		const char *opt;
		static struct option long_options[] = {
			{"file", 1, NULL, 0},
			{"version", 0, NULL, 0},
			{"help", 0, NULL, 0},
			{NULL, 0, NULL, 0}
		};

		c = getopt_long (argc, argv, "",
				 long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			opt = long_options[option_index].name;

			if (strcmp (opt, "help") == 0) {
				usage (argc, argv);
				return 0;
			} else if (strcmp (opt, "version") == 0) {
				is_version = TRUE;
			} else if (strcmp (opt, "file") == 0) {
                                file = g_strdup (optarg);
			}
			break;

		default:
			usage (argc, argv);
                        goto out;
		}
	}

	if (is_version) {
		printf ("pk-privilege-file-validate " PACKAGE_VERSION "\n");
                return 0;
	}

	if (file == NULL) {
		usage (argc, argv);
                goto out;
	}

        priv_file = libpolkit_privilege_file_new (file, &error);
        if (priv_file == NULL) {
                printf ("%s did not validate: %s\n", file, error->message);
                g_error_free (error);
                goto out;
        }

        validated = TRUE;
        libpolkit_privilege_file_unref (priv_file);

out:
        if (file != NULL)
                g_free (file);

        if (validated)
                return 0;
        else
                return 1;
}

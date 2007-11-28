/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file-validate.c : validate policy file
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
        execlp ("man", "man", "polkit-policy-file-validate", NULL);
        fprintf (stderr, "Cannot show man page: %m\n");
        exit (1);
}

static bool
validate_file (const char *file)
{
        PolKitPolicyFile *priv_file;
        PolKitError *error;

        error = NULL;
        priv_file = polkit_policy_file_new (file, TRUE, &error);
        if (priv_file == NULL) {
                printf ("%s did not validate: %s\n", file, polkit_error_get_error_message (error));
                polkit_error_free (error);
                return FALSE;
        }
        polkit_policy_file_unref (priv_file);
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

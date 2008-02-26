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

#include <kit/kit.h>
#include <polkit/polkit.h>

static polkit_bool_t warned = FALSE;

static void
usage (int argc, char *argv[])
{
        execlp ("man", "man", "polkit-policy-file-validate", NULL);
        fprintf (stderr, "Cannot show man page: %m\n");
        exit (1);
}

static polkit_bool_t
entry_foreach_cb (PolKitPolicyFile      *policy_file, 
                  PolKitPolicyFileEntry *policy_file_entry,
                  void                  *user_data)
{
        const char *id;
        const char *prefix = user_data;

        id = polkit_policy_file_entry_get_id (policy_file_entry);
        if (!kit_str_has_prefix (id, prefix) || 
            strchr (id + strlen (prefix), '.') != NULL) {
                printf ("WARNING: The action %s does not\n"
                        "         belong in a policy file named %spolicy.\n"
                        "         A future version of PolicyKit will ignore this action.\n"
                        "\n", 
                        id, prefix);
                warned = TRUE;
        }

        return FALSE;
}

static polkit_bool_t
validate_file (const char *file)
{
        PolKitPolicyFile *policy_file;
        PolKitError *error;
        char *prefix;
        polkit_bool_t ret;
        const char *basename;

        ret = FALSE;
        prefix = NULL;
        policy_file = NULL;

        if (!kit_str_has_suffix (file, ".policy")) {
                printf ("%s doesn't have a .policy suffix\n", file);
                goto out;
        }
        basename = strrchr (file, '/');
        if (basename != NULL)
                basename++;
        else
                basename = file;
        prefix = kit_strdup (basename);
        /* strip out "policy" - retain the dot */
        prefix [strlen (prefix) - 6] = '\0';

        error = NULL;
        policy_file = polkit_policy_file_new (file, TRUE, &error);
        if (policy_file == NULL) {
                printf ("%s did not validate: %s\n", file, polkit_error_get_error_message (error));
                polkit_error_free (error);
                goto out;
        }
        warned = FALSE;
        polkit_policy_file_entry_foreach (policy_file, entry_foreach_cb, prefix);
        if (warned) {
                goto out;
        }

        ret = TRUE;
out:
        kit_free (prefix);
        if (policy_file != NULL)
                polkit_policy_file_unref (policy_file);
        return ret;
}

int
main (int argc, char *argv[])
{
        int n;
        int ret;

	if (argc <= 1) {
		usage (argc, argv);
                ret = 1;
                goto out;
	}

        ret = 0;
        for (n = 1; n < argc; n++) {
                if (strcmp (argv[n], "--help") == 0) {
                        usage (argc, argv);
                        goto out;
                }
                if (strcmp (argv[n], "--version") == 0) {
                        printf ("polkit-policy-file-validate " PACKAGE_VERSION "\n");
                        goto out;
                }

                if (!validate_file (argv[n])) {
                        printf ("ERROR: %s did not validate\n"
                                "\n", 
                                argv[n]);
                        ret = 1;
                }
	}

out:
        return ret;
}

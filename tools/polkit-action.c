/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-action.c : list all registered PolicyKit actions
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
        execlp ("man", "man", "polkit-action", NULL);
        fprintf (stderr, "Cannot show man page: %m\n");
        exit (1);
}

static polkit_bool_t
_print_annotations (PolKitPolicyFileEntry *policy_file_entry,
                    const char *key,
                    const char *value,
                    void *user_data)
{
        printf ("annotation:       %s -> %s\n", key, value);
        return FALSE;
}

static void
_print_details_for_entry (PolKitPolicyFileEntry *pfe)
{
        int n;
        const char *action_id;
        PolKitPolicyDefault *def;
        PolKitPolicyDefault *def_factory;

        action_id = polkit_policy_file_entry_get_id (pfe);
        def = polkit_policy_file_entry_get_default (pfe);
        def_factory = polkit_policy_file_entry_get_default_factory (pfe);

        printf ("action_id:        %s\n"
                "description:      %s\n"
                "message:          %s\n",
                action_id,
                polkit_policy_file_entry_get_action_description (pfe),
                polkit_policy_file_entry_get_action_message (pfe));

        for (n = 0; n < 3; n++) {
                PolKitResult result;
                PolKitResult result_factory;
                char *str;

                switch (n) {
                default:
                case 0:
                        str = "default_any:     ";
                        result = polkit_policy_default_get_allow_any (def);
                        result_factory = polkit_policy_default_get_allow_any (def_factory);
                        break;
                case 1:
                        str = "default_inactive:";
                        result = polkit_policy_default_get_allow_inactive (def);
                        result_factory = polkit_policy_default_get_allow_inactive (def_factory);
                        break;
                case 2:
                        str = "default_active:  ";
                        result = polkit_policy_default_get_allow_active (def);
                        result_factory = polkit_policy_default_get_allow_active (def_factory);
                        break;
                }

                if (result == result_factory) {
                        printf ("%s %s\n", str, polkit_result_to_string_representation (result));
                } else {
                        printf ("%s %s (factory default: %s)\n", str, 
                                polkit_result_to_string_representation (result),
                                polkit_result_to_string_representation (result_factory));
                }
        }

        polkit_policy_file_entry_annotations_foreach (pfe, _print_annotations, NULL);
}

static polkit_bool_t
_print_entry (PolKitPolicyCache *policy_cache,
              PolKitPolicyFileEntry *pfe,
              void *user_data)
{
        const char *action_id;

        action_id = polkit_policy_file_entry_get_id (pfe);
        printf ("%s\n", action_id);

        return FALSE;
}

static polkit_bool_t
_print_entry_override (PolKitPolicyCache *policy_cache,
                       PolKitPolicyFileEntry *pfe,
                       void *user_data)
{
        const char *action_id;
        PolKitPolicyDefault *def;
        PolKitPolicyDefault *def_factory;

        def = polkit_policy_file_entry_get_default (pfe);
        def_factory = polkit_policy_file_entry_get_default_factory (pfe);

        if (!polkit_policy_default_equals (def, def_factory)) {
                action_id = polkit_policy_file_entry_get_id (pfe);
                printf ("%s\n", action_id);
        }

        return FALSE;
}

int
main (int argc, char *argv[])
{
        int n;
        int ret;
        PolKitContext *ctx;
        PolKitPolicyCache *cache;
        PolKitError *error;
        char *action_id;
        char *reset_action_id;
        char *set_def_any_action_id;
        char *set_def_inactive_action_id;
        char *set_def_active_action_id;
        PolKitResult set_def_any_value;
        PolKitResult set_def_inactive_value;
        PolKitResult set_def_active_value;
        polkit_bool_t show_overrides;

        ret = 1;
        action_id = NULL;
        reset_action_id = NULL;
        set_def_any_action_id = NULL;
        set_def_inactive_action_id = NULL;
        set_def_active_action_id = NULL;
        show_overrides = FALSE;

        for (n = 1; n < argc; n++) {
                if (strcmp (argv[n], "--help") == 0) {
                        usage (argc, argv);
                        return 0;
                } else if (strcmp (argv[n], "--version") == 0) {
                        printf ("polkit-action " PACKAGE_VERSION "\n");
                        return 0;
                } else if (strcmp (argv[n], "--action") == 0 && n + 1 < argc) {
                        action_id = argv[++n];
                } else if (strcmp (argv[n], "--reset-defaults") == 0 && n + 1 < argc) {
                        reset_action_id = argv[++n];
                } else if (strcmp (argv[n], "--show-overrides") == 0) {
                        show_overrides = TRUE;
                } else if (strcmp (argv[n], "--set-defaults-any") == 0 && n + 2 < argc) {
                        set_def_any_action_id = argv[++n];
                        if (!polkit_result_from_string_representation (argv[++n], &set_def_any_value))
                                usage (argc, argv);
                } else if (strcmp (argv[n], "--set-defaults-inactive") == 0 && n + 2 < argc) {
                        set_def_inactive_action_id = argv[++n];
                        if (!polkit_result_from_string_representation (argv[++n], &set_def_inactive_value))
                                usage (argc, argv);
                } else if (strcmp (argv[n], "--set-defaults-active") == 0 && n + 2 < argc) {
                        set_def_active_action_id = argv[++n];
                        if (!polkit_result_from_string_representation (argv[++n], &set_def_active_value))
                                usage (argc, argv);
                } else {
                        usage (argc, argv);
                        return 0;
                }
	}

        ctx = polkit_context_new ();
        if (ctx == NULL)
                goto out;
        error = NULL;
        polkit_context_set_load_descriptions (ctx);
        if (!polkit_context_init (ctx, &error)) {
                fprintf (stderr, "Init failed: %s\n", polkit_error_get_error_message (error));
                polkit_context_unref (ctx);
                goto out;
        }

        cache = polkit_context_get_policy_cache (ctx);
        if (cache == NULL) {
                polkit_context_unref (ctx);
                goto out;
        }

        if (argc == 1) {
                polkit_policy_cache_foreach (cache, _print_entry, NULL);
                goto done;
        }

        if (show_overrides) {
                polkit_policy_cache_foreach (cache, _print_entry_override, NULL);
                goto done;
        }

        while (TRUE) {
                if (reset_action_id != NULL) {
                        PolKitPolicyDefault *def;
                        PolKitPolicyFileEntry *pfe;
                        PolKitError *pk_error;

                        pfe = polkit_policy_cache_get_entry_by_id (cache, reset_action_id);
                        if (pfe == NULL) {
                                fprintf (stderr, "Cannot find policy file entry for action id '%s'\n", reset_action_id);
                                goto out;
                        }
                        def = polkit_policy_file_entry_get_default_factory (pfe);

                        pk_error = NULL;
                        if (!polkit_policy_file_entry_set_default (pfe, def, &pk_error)) {
                                fprintf (stderr, "Error: code=%d: %s: %s\n",
                                         polkit_error_get_error_code (pk_error),
                                         polkit_error_get_error_name (pk_error),
                                         polkit_error_get_error_message (pk_error));
                                polkit_error_free (pk_error);
                                goto out;
                        }

                        reset_action_id = NULL;
                }

                if (set_def_any_action_id != NULL) {
                        PolKitPolicyDefault *def;
                        PolKitPolicyFileEntry *pfe;
                        PolKitError *pk_error;

                        pfe = polkit_policy_cache_get_entry_by_id (cache, set_def_any_action_id);
                        if (pfe == NULL) {
                                fprintf (stderr, "Cannot find policy file entry for action id '%s'\n", set_def_any_action_id);
                                goto out;
                        }

                        def = polkit_policy_default_clone (polkit_policy_file_entry_get_default (pfe));
                        polkit_policy_default_set_allow_any (def, set_def_any_value);
                        pk_error = NULL;
                        if (!polkit_policy_file_entry_set_default (pfe, def, &pk_error)) {
                                fprintf (stderr, "Error: code=%d: %s: %s\n",
                                         polkit_error_get_error_code (pk_error),
                                         polkit_error_get_error_name (pk_error),
                                         polkit_error_get_error_message (pk_error));
                                polkit_error_free (pk_error);
                                goto out;
                        }
                        polkit_policy_default_unref (def);

                        set_def_any_action_id = NULL;
                }

                if (set_def_inactive_action_id != NULL) {
                        PolKitPolicyDefault *def;
                        PolKitPolicyFileEntry *pfe;
                        PolKitError *pk_error;

                        pfe = polkit_policy_cache_get_entry_by_id (cache, set_def_inactive_action_id);
                        if (pfe == NULL) {
                                fprintf (stderr, "Cannot find policy file entry for action id '%s'\n", set_def_inactive_action_id);
                                goto out;
                        }

                        def = polkit_policy_default_clone (polkit_policy_file_entry_get_default (pfe));
                        polkit_policy_default_set_allow_inactive (def, set_def_inactive_value);
                        pk_error = NULL;
                        if (!polkit_policy_file_entry_set_default (pfe, def, &pk_error)) {
                                fprintf (stderr, "Error: code=%d: %s: %s\n",
                                         polkit_error_get_error_code (pk_error),
                                         polkit_error_get_error_name (pk_error),
                                         polkit_error_get_error_message (pk_error));
                                polkit_error_free (pk_error);
                                goto out;
                        }
                        polkit_policy_default_unref (def);

                        set_def_inactive_action_id = NULL;
                }

                if (set_def_active_action_id != NULL) {
                        PolKitPolicyDefault *def;
                        PolKitPolicyFileEntry *pfe;
                        PolKitError *pk_error;

                        pfe = polkit_policy_cache_get_entry_by_id (cache, set_def_active_action_id);
                        if (pfe == NULL) {
                                fprintf (stderr, "Cannot find policy file entry for action id '%s'\n", set_def_active_action_id);
                                goto out;
                        }

                        def = polkit_policy_default_clone (polkit_policy_file_entry_get_default (pfe));
                        polkit_policy_default_set_allow_active (def, set_def_active_value);
                        pk_error = NULL;
                        if (!polkit_policy_file_entry_set_default (pfe, def, &pk_error)) {
                                fprintf (stderr, "Error: code=%d: %s: %s\n",
                                         polkit_error_get_error_code (pk_error),
                                         polkit_error_get_error_name (pk_error),
                                         polkit_error_get_error_message (pk_error));
                                polkit_error_free (pk_error);
                                goto out;
                        }
                        polkit_policy_default_unref (def);

                        set_def_active_action_id = NULL;
                }
                
                if (action_id != NULL) {
                        PolKitPolicyFileEntry *pfe;
                        pfe = polkit_policy_cache_get_entry_by_id (cache, action_id);
                        if (pfe == NULL) {
                                fprintf (stderr, "Cannot find policy file entry for action id '%s'\n", action_id);
                                goto out;
                        }
                        _print_details_for_entry (pfe);

                        action_id = NULL;
                } else {
                        goto done;
                }
        }

done:

        polkit_context_unref (ctx);

        ret = 0;
out:
        return ret;
}

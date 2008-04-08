/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file-entry.c : entries in policy files
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include "polkit-debug.h"
#include "polkit-error.h"
#include "polkit-result.h"
#include "polkit-policy-file-entry.h"
#include "polkit-authorization-db.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-policy-file-entry
 * @title: Policy File Entry
 * @short_description: Represents a declared action in a policy file.
 *
 * This class is used to represent a entries in policy files.
 **/

/**
 * PolKitPolicyFileEntry:
 *
 * Objects of this class are used to record information about a
 * policy.
 **/
struct _PolKitPolicyFileEntry
{
        int refcount;
        char *action;
        PolKitPolicyDefault *defaults_factory;
        PolKitPolicyDefault *defaults;

        char *policy_description;
        char *policy_message;
        char *vendor;
        char *vendor_url;
        char *icon_name;
        KitHash *annotations;
};


/* NOTE: we take ownership of the annotations object */
PolKitPolicyFileEntry *
_polkit_policy_file_entry_new   (const char *action_id, 
                                 const char *vendor,
                                 const char *vendor_url,
                                 const char *icon_name,
                                 PolKitResult defaults_allow_any,
                                 PolKitResult defaults_allow_inactive,
                                 PolKitResult defaults_allow_active,
                                 KitHash *annotations)
{
        char *path;
        char *contents;
        size_t contents_size;
        PolKitPolicyFileEntry *pfe;

        path = NULL;
        contents = NULL;

        kit_return_val_if_fail (action_id != NULL && polkit_action_validate_id (action_id), NULL);

        pfe = kit_new0 (PolKitPolicyFileEntry, 1);
        if (pfe == NULL)
                goto error;
        pfe->refcount = 1;
        pfe->action = kit_strdup (action_id);
        if (pfe->action == NULL)
                goto error;

        pfe->vendor = NULL;
        pfe->vendor_url = NULL;
        pfe->icon_name = NULL;
        if (vendor != NULL && (pfe->vendor = kit_strdup (vendor)) == NULL)
                goto error;
        if (vendor_url != NULL && (pfe->vendor_url = kit_strdup (vendor_url)) == NULL)
                goto error;
        if (icon_name != NULL && (pfe->icon_name = kit_strdup (icon_name)) == NULL)
                goto error;

        if (! (polkit_authorization_db_get_capabilities () & POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN)) {
                /* if we don't support obtaining authorizations
                 * through authenticating, then make the defaults
                 * reflect this ...*/
                defaults_allow_any = POLKIT_RESULT_NO;
                defaults_allow_inactive = POLKIT_RESULT_NO;
                defaults_allow_active = POLKIT_RESULT_NO;
        }

        pfe->defaults_factory = _polkit_policy_default_new (defaults_allow_any,
                                                            defaults_allow_inactive,
                                                            defaults_allow_active);
        if (pfe->defaults_factory == NULL)
                goto error;

        pfe->defaults = polkit_policy_default_clone (pfe->defaults_factory);
        if (pfe->defaults == NULL)
                goto error;

#ifdef POLKIT_AUTHDB_DEFAULT
        /* read override file */
        path = kit_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/PolicyKit-public/%s.defaults-override", action_id);
        if (path == NULL)
                goto error;
        if (!kit_file_get_contents (path, &contents, &contents_size)) {
                /* it's not a failure if the file doesn't exist */
                if (errno != ENOENT)
                        goto error;

                errno = 0;
                contents = NULL;
        }

        if (contents != NULL) {
                char **tokens;
                size_t num_tokens;
                PolKitResult any;
                PolKitResult inactive;
                PolKitResult active;

                tokens = kit_strsplit (contents, ':', &num_tokens);
                if (num_tokens != 3)
                        goto error;

                if (!polkit_result_from_string_representation (tokens[0], &any)) {
                        goto error;
                }
                if (!polkit_result_from_string_representation (tokens[1], &inactive)) {
                        goto error;
                }
                if (!polkit_result_from_string_representation (tokens[2], &active)) {
                        goto error;
                }

                polkit_policy_default_set_allow_any      (pfe->defaults, any);
                polkit_policy_default_set_allow_inactive (pfe->defaults, inactive);
                polkit_policy_default_set_allow_active   (pfe->defaults, active);
        }
#endif

        pfe->annotations = annotations;

        kit_free (path);
        kit_free (contents);

        return pfe;
error:
        kit_free (path);
        kit_free (contents);
        if (pfe != NULL)
                polkit_policy_file_entry_unref (pfe);
        return NULL;
}

polkit_bool_t
_polkit_policy_file_entry_set_descriptions (PolKitPolicyFileEntry *pfe,
                                            const char *policy_description,
                                            const char *policy_message)
{
        kit_return_val_if_fail (pfe != NULL, FALSE);

        if (pfe->policy_description != NULL)
                kit_free (pfe->policy_description);
        if (pfe->policy_message != NULL)
                kit_free (pfe->policy_message);

        pfe->policy_description = kit_strdup (policy_description);
        pfe->policy_message = kit_strdup (policy_message);

        if (policy_description != NULL && pfe->policy_description == NULL)
                return FALSE;

        if (policy_message != NULL && pfe->policy_message == NULL)
                return FALSE;

        return TRUE;
}

/**
 * polkit_policy_file_entry_get_action_description:
 * @policy_file_entry: the object
 * 
 * Get the description of the action that this policy entry describes. This
 * is intended to be used in policy editors, for example "Mount internal
 * volumes". Contrast with polkit_policy_file_entry_get_action_message(). The
 * textual string will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_entry_get_action_description (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->policy_description;
}

/**
 * polkit_policy_file_entry_get_action_message:
 * @policy_file_entry: the object
 * 
 * Get the message describing the action that this policy entry
 * describes. This is to be used in dialogs, for example "System
 * Policy prevents mounting this volume". Contrast with
 * polkit_policy_file_entry_get_action_description(). The textual string
 * will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_policy_file_entry_get_action_message (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->policy_message;
}

/**
 * polkit_policy_file_entry_get_action_vendor:
 * @policy_file_entry: the object
 * 
 * Get the name of the vendor of this action.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded or vendor
 * tag isn't set - caller shall not free this string
 *
 * Since: 0.7
 */
const char *
polkit_policy_file_entry_get_action_vendor     (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->vendor;
}

/**
 * polkit_policy_file_entry_get_action_vendor_url:
 * @policy_file_entry: the object
 * 
 * Get the URL of the vendor of this action.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded or vendor
 * url isn't set - caller shall not free this string
 *
 * Since: 0.7
 */
const char *
polkit_policy_file_entry_get_action_vendor_url (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->vendor_url;
}

/**
 * polkit_policy_file_entry_get_action_icon_name:
 * @policy_file_entry: the object
 * 
 * Get the name of the icon that represents the action. This name
 * conforms to the freedesktop.org icon naming specification.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded or icon
 * tag isn't set - caller shall not free this string
 *
 * Since: 0.7
 */
const char *
polkit_policy_file_entry_get_action_icon_name (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->icon_name;
}


/**
 * polkit_policy_file_entry_ref:
 * @policy_file_entry: the policy file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyFileEntry *
polkit_policy_file_entry_ref (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, policy_file_entry);
        policy_file_entry->refcount++;
        return policy_file_entry;
}

/**
 * polkit_policy_file_entry_unref:
 * @policy_file_entry: the policy file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_policy_file_entry_unref (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_if_fail (policy_file_entry != NULL);
        policy_file_entry->refcount--;
        if (policy_file_entry->refcount > 0) 
                return;

        kit_free (policy_file_entry->action);

        if (policy_file_entry->defaults_factory != NULL)
                polkit_policy_default_unref (policy_file_entry->defaults_factory);

        if (policy_file_entry->defaults != NULL)
                polkit_policy_default_unref (policy_file_entry->defaults);

        if (policy_file_entry->annotations != NULL)
                kit_hash_unref (policy_file_entry->annotations);

        kit_free (policy_file_entry->policy_description);
        kit_free (policy_file_entry->policy_message);
        kit_free (policy_file_entry->vendor);
        kit_free (policy_file_entry->vendor_url);
        kit_free (policy_file_entry->icon_name);

        kit_free (policy_file_entry);
}

/**
 * polkit_policy_file_entry_debug:
 * @policy_file_entry: the entry
 * 
 * Print debug information about object
 **/
void
polkit_policy_file_entry_debug (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_if_fail (policy_file_entry != NULL);
        _pk_debug ("PolKitPolicyFileEntry: refcount=%d action=%s",
                   policy_file_entry->refcount,
                   policy_file_entry->action);
        polkit_policy_default_debug (policy_file_entry->defaults);
}

/**
 * polkit_policy_file_entry_get_id:
 * @policy_file_entry: the file entry
 * 
 * Get the action identifier.
 * 
 * Returns: A string - caller shall not free this string.
 **/
const char *
polkit_policy_file_entry_get_id (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->action;
}

/**
 * polkit_policy_file_entry_get_default:
 * @policy_file_entry: the file entry
 * 
 * Get the the default policy for this policy.
 * 
 * Returns: A #PolKitPolicyDefault object - caller shall not unref or modify this object.
 **/
PolKitPolicyDefault *
polkit_policy_file_entry_get_default (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->defaults;
}

/**
 * polkit_policy_file_entry_get_default_factory:
 * @policy_file_entry: the file entry
 * 
 * Get the factory defaults for the entry. This may be different that
 * what polkit_policy_file_entry_get_default() returns if the function
 * polkit_policy_file_entry_set_default() have been used to change the
 * defaults.
 *
 * Returns: A #PolKitPolicyDefault object - caller shall not unref or modify this object.
 *
 * Since: 0.7
 */
PolKitPolicyDefault *
polkit_policy_file_entry_get_default_factory (PolKitPolicyFileEntry *policy_file_entry)
{
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        return policy_file_entry->defaults_factory;
}

/**
 * polkit_policy_file_entry_set_default:
 * @policy_file_entry: the file entry
 * @defaults: the new defaults to set
 * @error: return location for error or #NULL
 *
 * Set new defaults for a given policy file entry; subsequent calls to
 * polkit_policy_file_get_default() will return these values. Note
 * that the old defaults are not modified; they are still available via
 * polkit_policy_file_entry_get_default_factory().
 *
 * This operation requires the
 * org.freedesktop.policykit.modify-defaults authorization and will
 * fail if the caller lacks it.
 *
 * Returns: %TRUE if the given defaults was set; %FALSE if @error is set.
 *
 * Since: 0.7
 */
polkit_bool_t
polkit_policy_file_entry_set_default (PolKitPolicyFileEntry  *policy_file_entry,
                                      PolKitPolicyDefault    *defaults,
                                      PolKitError           **error)
{
        polkit_bool_t ret;

        ret = FALSE;

        kit_return_val_if_fail (policy_file_entry != NULL, FALSE);
        kit_return_val_if_fail (defaults != NULL, FALSE);

#ifndef POLKIT_AUTHDB_DEFAULT
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
#else
        char *helper_argv[7] = {PACKAGE_LIBEXEC_DIR "/polkit-set-default-helper", 
                                NULL, /* arg1: action_id */
                                NULL, /* arg2: "clear" or "set" */
                                NULL, /* arg3: result_any */
                                NULL, /* arg4: result_inactive */
                                NULL, /* arg5: result_active */
                                NULL};
        int exit_status;
        PolKitResult any;
        PolKitResult inactive;
        PolKitResult active;

        if (polkit_policy_default_equals (policy_file_entry->defaults, defaults)) {
                /* no point in doing extra work.. */
                ret = TRUE;
                goto out;
        }

        any = polkit_policy_default_get_allow_any (defaults);
        inactive = polkit_policy_default_get_allow_inactive (defaults);
        active = polkit_policy_default_get_allow_active (defaults);

        helper_argv[1] = policy_file_entry->action;

        if (polkit_policy_default_equals (policy_file_entry->defaults_factory, defaults)) {
                helper_argv[2] = "clear";
                helper_argv[3] = NULL;
        } else {
                helper_argv[2] = "set";
                helper_argv[3] = (char *) polkit_result_to_string_representation (any);
                helper_argv[4] = (char *) polkit_result_to_string_representation (inactive);
                helper_argv[5] = (char *) polkit_result_to_string_representation (active);
                helper_argv[6] = NULL;
        }

        if (!kit_spawn_sync (NULL,             /* const char  *working_directory */
                             0,                /* flags */
                             helper_argv,      /* char       **argv */
                             NULL,             /* char       **envp */
                             NULL,             /* char        *stdin */
                             NULL,             /* char       **stdout */
                             NULL,             /* char       **stderr */
                             &exit_status)) {  /* int         *exit_status */
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "Error spawning set-default helper: %m");
                goto out;
        }

        if (!WIFEXITED (exit_status)) {
                kit_warning ("Set-default helper crashed!");
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_GENERAL_ERROR, 
                                        "set-default helper crashed!");
                goto out;
        } else if (WEXITSTATUS(exit_status) != 0) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_NOT_AUTHORIZED_TO_MODIFY_DEFAULTS, 
                                        "uid %d is not authorized to modify defaults for implicit authorization for action %s (requires org.freedesktop.policykit.modify-defaults)",
                                        getuid (), policy_file_entry->action);
        } else {
                ret = TRUE;
        }
out:
#endif /* POLKIT_AUTHDB_DEFAULT */
        return ret;
}


typedef struct  {
        PolKitPolicyFileEntry *pfe;
        PolKitPolicyFileEntryAnnotationsForeachFunc cb;
        void *user_data;
} _AnnotationsClosure;

static polkit_bool_t
_annotations_cb (KitHash *hash,
                 void *key,
                 void *value,
                 void *user_data)
{
        _AnnotationsClosure *closure = user_data;
        return closure->cb (closure->pfe, (const char *) key, (const char *) value, closure->user_data);
}

/**
 * polkit_policy_file_entry_annotations_foreach:
 * @policy_file_entry: the policy file entry
 * @cb: callback function
 * @user_data: user data to pass to the callback function
 *
 * Iterate over all annotations on the policy file entry.
 *
 * Returns: #TRUE only if the iteration was short-circuited
 */
polkit_bool_t
polkit_policy_file_entry_annotations_foreach (PolKitPolicyFileEntry *policy_file_entry,
                                              PolKitPolicyFileEntryAnnotationsForeachFunc cb,
                                              void *user_data)
{
        _AnnotationsClosure closure;

        kit_return_val_if_fail (policy_file_entry != NULL, FALSE);
        if (policy_file_entry->annotations == NULL)
                return FALSE;

        closure.pfe = policy_file_entry;
        closure.cb = cb;
        closure.user_data = user_data;

        return kit_hash_foreach (policy_file_entry->annotations,
                                    _annotations_cb,
                                    &closure);
}

/**
 * polkit_policy_file_entry_get_annotation:
 * @policy_file_entry: the policy file entry
 * @key: the key of the annotation
 *
 * Look of the value of a given annotation.
 *
 * Returns: The value of the annotation or #NULL if not found.
 */
const char *
polkit_policy_file_entry_get_annotation (PolKitPolicyFileEntry *policy_file_entry,
                                         const char *key)
{
        const char *value;
        kit_return_val_if_fail (policy_file_entry != NULL, NULL);
        kit_return_val_if_fail (key != NULL, NULL);

        value = NULL;
        if (policy_file_entry->annotations != NULL) {
                value = kit_hash_lookup (policy_file_entry->annotations, (void *) key, NULL);
        }
        return value;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_pfe_cb (PolKitPolicyFileEntry *pfe,
         const char *key,
         const char *value,
         void *user_data)
{
        int *count = (int *) user_data;

        if (strcmp (key, "a1") == 0 && strcmp (value, "v1") == 0)
                *count += 1;
        else if (strcmp (key, "a2") == 0 && strcmp (value, "v2") == 0)
                *count += 1;

        return FALSE;
}

static polkit_bool_t
_pfe_cb2 (PolKitPolicyFileEntry *pfe,
          const char *key,
          const char *value,
          void *user_data)
{
        int *count = (int *) user_data;
        *count += 1;

        return FALSE;
}


static polkit_bool_t
_run_test (void)
{
        PolKitPolicyFileEntry *pfe;
        PolKitPolicyDefault *d;
        KitHash *a;
        int count;

        a = NULL;
        pfe = NULL;

        if ((a = kit_hash_new (kit_hash_str_hash_func,
                               kit_hash_str_equal_func,
                               NULL, NULL,
                               NULL, NULL)) == NULL)
                goto oom;

        if (!kit_hash_insert (a, "a1", "v1"))
                goto oom;

        if (!kit_hash_insert (a, "a2", "v2"))
                goto oom;

        if ((pfe = _polkit_policy_file_entry_new ("org.example-action",
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  POLKIT_RESULT_NO,
                                                  POLKIT_RESULT_ONLY_VIA_SELF_AUTH,
                                                  POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH,
                                                  a)) == NULL)
                goto oom;
        /* _file_entry_new assumes ownership of the passed a variable */
        a = NULL;

        kit_assert (strcmp (polkit_policy_file_entry_get_id (pfe), "org.example-action") == 0);
        
        if (_polkit_policy_file_entry_set_descriptions (pfe,
                                                        "the desc",
                                                        "the msg")) {
                kit_assert (strcmp (polkit_policy_file_entry_get_action_description (pfe), "the desc") == 0);
                kit_assert (strcmp (polkit_policy_file_entry_get_action_message (pfe), "the msg") == 0);
        }
        
        if (_polkit_policy_file_entry_set_descriptions (pfe,
                                                        "the desc2",
                                                        "the msg2")) {
                kit_assert (strcmp (polkit_policy_file_entry_get_action_description (pfe), "the desc2") == 0);
                kit_assert (strcmp (polkit_policy_file_entry_get_action_message (pfe), "the msg2") == 0);
        }
        
        kit_assert ((d = polkit_policy_file_entry_get_default (pfe)) != NULL);

#ifdef POLKIT_AUTHDB_DEFAULT
        kit_assert (polkit_policy_default_get_allow_any (d) == POLKIT_RESULT_NO);
        kit_assert (polkit_policy_default_get_allow_inactive (d) == POLKIT_RESULT_ONLY_VIA_SELF_AUTH);
        kit_assert (polkit_policy_default_get_allow_active (d) == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH);
#endif
        
        polkit_policy_file_entry_ref (pfe);
        polkit_policy_file_entry_unref (pfe);
        polkit_policy_file_entry_debug (pfe);

        kit_assert (strcmp (polkit_policy_file_entry_get_annotation (pfe, "a1"), "v1") == 0);
        kit_assert (strcmp (polkit_policy_file_entry_get_annotation (pfe, "a2"), "v2") == 0);
        kit_assert (polkit_policy_file_entry_get_annotation (pfe, "a3") == NULL);

        count = 0;
        polkit_policy_file_entry_annotations_foreach (pfe, _pfe_cb, &count);
        kit_assert (count == 2);

        polkit_policy_file_entry_unref (pfe);
        if ((pfe = _polkit_policy_file_entry_new ("org.example-action-2",
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  POLKIT_RESULT_NO,
                                                  POLKIT_RESULT_ONLY_VIA_SELF_AUTH,
                                                  POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH,
                                                  NULL)) == NULL)
                goto oom;
        count = 0;
        polkit_policy_file_entry_annotations_foreach (pfe, _pfe_cb2, &count);
        kit_assert (count == 0);
        _pfe_cb2 (pfe, NULL, NULL, &count); /* want to get coverage of _pfe_cb2 */
        kit_assert (count == 1);

oom:
        if (pfe != NULL)
                polkit_policy_file_entry_unref (pfe);

        if (a != NULL)
                kit_hash_unref (a);

        return TRUE;
}

KitTest _test_policy_file_entry = {
        "polkit_policy_file_entry",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

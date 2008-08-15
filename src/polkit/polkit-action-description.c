/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-action-description.c : Description of an action
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
#include "polkit-action-description.h"
#include "polkit-authorization-db.h"
#include "polkit-private.h"
#include "polkit-test.h"
#include "polkit-private.h"

/**
 * SECTION:polkit-action-description
 * @title: Action Description
 * @short_description: Represents a declared action in a policy file.
 *
 * This class is used to represent a entries in policy files.
 **/

/**
 * PolKitActionDescription:
 *
 * Objects of this class are used to record information about a
 * policy.
 **/
struct _PolKitActionDescription
{
        int refcount;
        char *action;
        PolKitImplicitAuthorization *implicit_authorization_factory;
        PolKitImplicitAuthorization *implicit_authorization;

        char *policy_description;
        char *policy_message;
        char *vendor;
        char *vendor_url;
        char *icon_name;
        KitHash *annotations;
};


/* NOTE: we take ownership of the annotations object */
PolKitActionDescription *
_polkit_action_description_new   (const char *action_id, 
                                 const char *vendor,
                                 const char *vendor_url,
                                 const char *icon_name,
                                 PolKitResult implicit_authorization_allow_any,
                                 PolKitResult implicit_authorization_allow_inactive,
                                 PolKitResult implicit_authorization_allow_active,
                                 KitHash *annotations)
{
        char *path;
        char *contents;
        size_t contents_size;
        PolKitActionDescription *pfe;

        path = NULL;
        contents = NULL;

        kit_return_val_if_fail (action_id != NULL && polkit_action_validate_id (action_id), NULL);

        pfe = kit_new0 (PolKitActionDescription, 1);
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
                 * through authenticating, then make the implicit_authorization
                 * reflect this ...*/
                implicit_authorization_allow_any = POLKIT_RESULT_NO;
                implicit_authorization_allow_inactive = POLKIT_RESULT_NO;
                implicit_authorization_allow_active = POLKIT_RESULT_NO;
        }

        pfe->implicit_authorization_factory = _polkit_implicit_authorization_new (implicit_authorization_allow_any,
                                                            implicit_authorization_allow_inactive,
                                                            implicit_authorization_allow_active);
        if (pfe->implicit_authorization_factory == NULL)
                goto error;

        pfe->implicit_authorization = polkit_implicit_authorization_clone (pfe->implicit_authorization_factory);
        if (pfe->implicit_authorization == NULL)
                goto error;

#ifdef POLKIT_AUTHDB_DEFAULT
        /* read override file */
        path = kit_strdup_printf (PACKAGE_LOCALSTATE_DIR "/lib/polkit-public-1/%s.defaults-override", action_id);
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

                polkit_implicit_authorization_set_allow_any      (pfe->implicit_authorization, any);
                polkit_implicit_authorization_set_allow_inactive (pfe->implicit_authorization, inactive);
                polkit_implicit_authorization_set_allow_active   (pfe->implicit_authorization, active);
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
                polkit_action_description_unref (pfe);
        return NULL;
}

polkit_bool_t
_polkit_action_description_set_descriptions (PolKitActionDescription *pfe,
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
 * polkit_action_description_get_action_description:
 * @action_description: the object
 * 
 * Get the description of the action that this policy entry describes. This
 * is intended to be used in policy editors, for example "Mount internal
 * volumes". Contrast with polkit_action_description_get_action_message(). The
 * textual string will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_action_description_get_action_description (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->policy_description;
}

/**
 * polkit_action_description_get_action_message:
 * @action_description: the object
 * 
 * Get the message describing the action that this policy entry
 * describes. This is to be used in dialogs, for example "System
 * Policy prevents mounting this volume". Contrast with
 * polkit_action_description_get_action_description(). The textual string
 * will be returned in the current locale.
 *
 * Note, if polkit_context_set_load_descriptions() on the
 * #PolKitContext object used to get this object wasn't called, this
 * method will return #NULL.
 * 
 * Returns: string or #NULL if descriptions are not loaded - caller shall not free this string
 **/
const char *
polkit_action_description_get_action_message (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->policy_message;
}

/**
 * polkit_action_description_get_action_vendor:
 * @action_description: the object
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
polkit_action_description_get_action_vendor     (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->vendor;
}

/**
 * polkit_action_description_get_action_vendor_url:
 * @action_description: the object
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
polkit_action_description_get_action_vendor_url (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->vendor_url;
}

/**
 * polkit_action_description_get_action_icon_name:
 * @action_description: the object
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
polkit_action_description_get_action_icon_name (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->icon_name;
}


/**
 * polkit_action_description_ref:
 * @action_description: the policy file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitActionDescription *
polkit_action_description_ref (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, action_description);
        action_description->refcount++;
        return action_description;
}

/**
 * polkit_action_description_unref:
 * @action_description: the policy file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_action_description_unref (PolKitActionDescription *action_description)
{
        kit_return_if_fail (action_description != NULL);
        action_description->refcount--;
        if (action_description->refcount > 0) 
                return;

        kit_free (action_description->action);

        if (action_description->implicit_authorization_factory != NULL)
                polkit_implicit_authorization_unref (action_description->implicit_authorization_factory);

        if (action_description->implicit_authorization != NULL)
                polkit_implicit_authorization_unref (action_description->implicit_authorization);

        if (action_description->annotations != NULL)
                kit_hash_unref (action_description->annotations);

        kit_free (action_description->policy_description);
        kit_free (action_description->policy_message);
        kit_free (action_description->vendor);
        kit_free (action_description->vendor_url);
        kit_free (action_description->icon_name);

        kit_free (action_description);
}

/**
 * polkit_action_description_debug:
 * @action_description: the entry
 * 
 * Print debug information about object
 **/
void
polkit_action_description_debug (PolKitActionDescription *action_description)
{
        kit_return_if_fail (action_description != NULL);
        polkit_debug ("PolKitActionDescription: refcount=%d action=%s",
                      action_description->refcount,
                      action_description->action);
        polkit_implicit_authorization_debug (action_description->implicit_authorization);
}

/**
 * polkit_action_description_get_id:
 * @action_description: the file entry
 * 
 * Get the action identifier.
 * 
 * Returns: A string - caller shall not free this string.
 **/
const char *
polkit_action_description_get_id (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->action;
}

/**
 * polkit_action_description_get_implicit_authorization:
 * @action_description: the file entry
 * 
 * Get the the default policy for this policy.
 * 
 * Returns: A #PolKitImplicitAuthorization object - caller shall not unref or modify this object.
 **/
PolKitImplicitAuthorization *
polkit_action_description_get_implicit_authorization (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->implicit_authorization;
}

/**
 * polkit_action_description_get_implicit_authorization_factory:
 * @action_description: the file entry
 * 
 * Get the factory defaults for the entry. This may be different that
 * what polkit_action_description_get_implicit_authorization() returns if the function
 * polkit_action_description_set_implicit_authorization() have been used to change the
 * defaults.
 *
 * Returns: A #PolKitImplicitAuthorization object - caller shall not unref or modify this object.
 *
 * Since: 0.7
 */
PolKitImplicitAuthorization *
polkit_action_description_get_implicit_authorization_factory (PolKitActionDescription *action_description)
{
        kit_return_val_if_fail (action_description != NULL, NULL);
        return action_description->implicit_authorization_factory;
}

/**
 * polkit_action_description_set_implicit_authorization:
 * @action_description: the file entry
 * @implicit_authorization: the new defaults to set
 * @error: return location for error or #NULL
 *
 * Set new defaults for a given policy file entry; subsequent calls to
 * polkit_policy_file_get_default() will return these values. Note
 * that the old defaults are not modified; they are still available via
 * polkit_action_description_get_default_factory().
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
polkit_action_description_set_implicit_authorization (PolKitActionDescription  *action_description,
                                                      PolKitImplicitAuthorization    *implicit_authorization,
                                                      PolKitError           **error)
{
        polkit_bool_t ret;

        ret = FALSE;

        kit_return_val_if_fail (action_description != NULL, FALSE);
        kit_return_val_if_fail (implicit_authorization != NULL, FALSE);

#ifndef POLKIT_AUTHDB_DEFAULT
        polkit_error_set_error (error, POLKIT_ERROR_NOT_SUPPORTED, "Not supported");
#else
        char *helper_argv[7] = {PACKAGE_LIBEXEC_DIR "/polkit-set-default-helper-1", 
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

        if (polkit_implicit_authorization_equals (action_description->implicit_authorization, implicit_authorization)) {
                /* no point in doing extra work.. */
                ret = TRUE;
                goto out;
        }

        any = polkit_implicit_authorization_get_allow_any (implicit_authorization);
        inactive = polkit_implicit_authorization_get_allow_inactive (implicit_authorization);
        active = polkit_implicit_authorization_get_allow_active (implicit_authorization);

        helper_argv[1] = action_description->action;

        if (polkit_implicit_authorization_equals (action_description->implicit_authorization_factory, implicit_authorization)) {
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
                                        getuid (), action_description->action);
        } else {
                ret = TRUE;
        }
out:
#endif /* POLKIT_AUTHDB_DEFAULT */
        return ret;
}


typedef struct  {
        PolKitActionDescription *pfe;
        PolKitActionDescriptionAnnotationsForeachFunc cb;
        void *user_data;
} _AnnotationsClosure;

static polkit_bool_t
_annotations_cb (void *key,
                 void *value,
                 void *user_data,
                 KitHash *hash)
{
        _AnnotationsClosure *closure = user_data;
        return closure->cb (closure->pfe, (const char *) key, (const char *) value, closure->user_data);
}

/**
 * polkit_action_description_annotations_foreach:
 * @action_description: the policy file entry
 * @cb: callback function
 * @user_data: user data to pass to the callback function
 *
 * Iterate over all annotations on the policy file entry.
 *
 * Returns: #TRUE only if the iteration was short-circuited
 */
polkit_bool_t
polkit_action_description_annotations_foreach (PolKitActionDescription *action_description,
                                              PolKitActionDescriptionAnnotationsForeachFunc cb,
                                              void *user_data)
{
        _AnnotationsClosure closure;

        kit_return_val_if_fail (action_description != NULL, FALSE);
        if (action_description->annotations == NULL)
                return FALSE;

        closure.pfe = action_description;
        closure.cb = cb;
        closure.user_data = user_data;

        return kit_hash_foreach (action_description->annotations,
                                 _annotations_cb,
                                 &closure);
}

/**
 * polkit_action_description_get_annotation:
 * @action_description: the policy file entry
 * @key: the key of the annotation
 *
 * Look of the value of a given annotation.
 *
 * Returns: The value of the annotation or #NULL if not found.
 */
const char *
polkit_action_description_get_annotation (PolKitActionDescription *action_description,
                                         const char *key)
{
        const char *value;
        kit_return_val_if_fail (action_description != NULL, NULL);
        kit_return_val_if_fail (key != NULL, NULL);

        value = NULL;
        if (action_description->annotations != NULL) {
                value = kit_hash_lookup (action_description->annotations, (void *) key, NULL);
        }
        return value;
}


#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_pfe_cb (PolKitActionDescription *pfe,
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
_pfe_cb2 (PolKitActionDescription *pfe,
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
        PolKitActionDescription *pfe;
        PolKitImplicitAuthorization *d;
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

        if ((pfe = _polkit_action_description_new ("org.example-action",
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

        kit_assert (strcmp (polkit_action_description_get_id (pfe), "org.example-action") == 0);
        
        if (_polkit_action_description_set_descriptions (pfe,
                                                        "the desc",
                                                        "the msg")) {
                kit_assert (strcmp (polkit_action_description_get_action_description (pfe), "the desc") == 0);
                kit_assert (strcmp (polkit_action_description_get_action_message (pfe), "the msg") == 0);
        }
        
        if (_polkit_action_description_set_descriptions (pfe,
                                                        "the desc2",
                                                        "the msg2")) {
                kit_assert (strcmp (polkit_action_description_get_action_description (pfe), "the desc2") == 0);
                kit_assert (strcmp (polkit_action_description_get_action_message (pfe), "the msg2") == 0);
        }
        
        kit_assert ((d = polkit_action_description_get_default (pfe)) != NULL);

#ifdef POLKIT_AUTHDB_DEFAULT
        kit_assert (polkit_implicit_authorization_get_allow_any (d) == POLKIT_RESULT_NO);
        kit_assert (polkit_implicit_authorization_get_allow_inactive (d) == POLKIT_RESULT_ONLY_VIA_SELF_AUTH);
        kit_assert (polkit_implicit_authorization_get_allow_active (d) == POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH);
#endif
        
        polkit_action_description_ref (pfe);
        polkit_action_description_unref (pfe);
        polkit_action_description_debug (pfe);

        kit_assert (strcmp (polkit_action_description_get_annotation (pfe, "a1"), "v1") == 0);
        kit_assert (strcmp (polkit_action_description_get_annotation (pfe, "a2"), "v2") == 0);
        kit_assert (polkit_action_description_get_annotation (pfe, "a3") == NULL);

        count = 0;
        polkit_action_description_annotations_foreach (pfe, _pfe_cb, &count);
        kit_assert (count == 2);

        polkit_action_description_unref (pfe);
        if ((pfe = _polkit_action_description_new ("org.example-action-2",
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  POLKIT_RESULT_NO,
                                                  POLKIT_RESULT_ONLY_VIA_SELF_AUTH,
                                                  POLKIT_RESULT_ONLY_VIA_ADMIN_AUTH,
                                                  NULL)) == NULL)
                goto oom;
        count = 0;
        polkit_action_description_annotations_foreach (pfe, _pfe_cb2, &count);
        kit_assert (count == 0);
        _pfe_cb2 (pfe, NULL, NULL, &count); /* want to get coverage of _pfe_cb2 */
        kit_assert (count == 1);

oom:
        if (pfe != NULL)
                polkit_action_description_unref (pfe);

        if (a != NULL)
                kit_hash_unref (a);

        return TRUE;
}

KitTest _test_action_description = {
        "polkit_action_description",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */



#include <expat.h>
#include "polkit-context.h"

enum {
        STATE_NONE,
        STATE_UNKNOWN_TAG,
        STATE_IN_POLICY_CONFIG,
        STATE_IN_POLICY_VENDOR,
        STATE_IN_POLICY_VENDOR_URL,
        STATE_IN_POLICY_ICON_NAME,
        STATE_IN_ACTION,
        STATE_IN_ACTION_DESCRIPTION,
        STATE_IN_ACTION_MESSAGE,
        STATE_IN_ACTION_VENDOR,
        STATE_IN_ACTION_VENDOR_URL,
        STATE_IN_ACTION_ICON_NAME,
        STATE_IN_DEFAULTS,
        STATE_IN_DEFAULTS_ALLOW_ANY,
        STATE_IN_DEFAULTS_ALLOW_INACTIVE,
        STATE_IN_DEFAULTS_ALLOW_ACTIVE,
        STATE_IN_ANNOTATE
};

#define PARSER_MAX_DEPTH 32

typedef struct {
        XML_Parser parser;
        int state;
        int state_stack[PARSER_MAX_DEPTH];
        int stack_depth;

        const char *path;

        char *global_vendor;
        char *global_vendor_url;
        char *global_icon_name;

        char *action_id;
        char *vendor;
        char *vendor_url;
        char *icon_name;

        PolKitResult defaults_allow_any;
        PolKitResult defaults_allow_inactive;
        PolKitResult defaults_allow_active;
        
        KitHash *policy_descriptions;
        KitHash *policy_messages;

        char *policy_description_nolang;
        char *policy_message_nolang;

        /* the language according to $LANG (e.g. en_US, da_DK, fr, en_CA minus the encoding) */
        char *lang;

        /* the value of xml:lang for the thing we're reading in _cdata() */
        char *elem_lang;

        char *annotate_key;
        KitHash *annotations;

        polkit_bool_t is_oom;

        PolKitActionDescriptionForeachFunc cb;
        void *user_data;
} ParserData;

static void
pd_unref_action_data (ParserData *pd)
{
        kit_free (pd->action_id);
        pd->action_id = NULL;

        kit_free (pd->vendor);
        pd->vendor = NULL;
        kit_free (pd->vendor_url);
        pd->vendor_url = NULL;
        kit_free (pd->icon_name);
        pd->icon_name = NULL;

        kit_free (pd->policy_description_nolang);
        pd->policy_description_nolang = NULL;
        kit_free (pd->policy_message_nolang);
        pd->policy_message_nolang = NULL;
        if (pd->policy_descriptions != NULL) {
                kit_hash_unref (pd->policy_descriptions);
                pd->policy_descriptions = NULL;
        }
        if (pd->policy_messages != NULL) {
                kit_hash_unref (pd->policy_messages);
                pd->policy_messages = NULL;
        }
        kit_free (pd->annotate_key);
        pd->annotate_key = NULL;
        if (pd->annotations != NULL) {
                kit_hash_unref (pd->annotations);
                pd->annotations = NULL;
        }
        kit_free (pd->elem_lang);
        pd->elem_lang = NULL;
}

static void
pd_unref_data (ParserData *pd)
{
        pd_unref_action_data (pd);
        kit_free (pd->lang);
        pd->lang = NULL;

        kit_free (pd->global_vendor);
        pd->global_vendor = NULL;
        kit_free (pd->global_vendor_url);
        pd->global_vendor_url = NULL;
        kit_free (pd->global_icon_name);
        pd->global_icon_name = NULL;
}

static void
_start (void *data, const char *el, const char **attr)
{
        int state;
        int num_attr;
        ParserData *pd = data;

        for (num_attr = 0; attr[num_attr] != NULL; num_attr++)
                ;

        state = STATE_NONE;

        switch (pd->state) {
        case STATE_NONE:
                if (strcmp (el, "policyconfig") == 0) {
                        state = STATE_IN_POLICY_CONFIG;
                }
                break;
        case STATE_IN_POLICY_CONFIG:
                if (strcmp (el, "action") == 0) {
                        if (num_attr != 2 || strcmp (attr[0], "id") != 0)
                                goto error;
                        state = STATE_IN_ACTION;

                        if (!polkit_action_validate_id (attr[1]))
                                goto error;

                        pd_unref_action_data (pd);
                        pd->action_id = kit_strdup (attr[1]);
                        if (pd->action_id == NULL)
                                goto oom;
                        pd->policy_descriptions = kit_hash_new (kit_hash_str_hash_func, 
                                                                kit_hash_str_equal_func, 
                                                                kit_hash_str_copy, kit_hash_str_copy,
                                                                kit_free, kit_free);
                        pd->policy_messages = kit_hash_new (kit_hash_str_hash_func, 
                                                            kit_hash_str_equal_func, 
                                                            kit_hash_str_copy, kit_hash_str_copy,
                                                            kit_free, kit_free);

                        /* initialize defaults */
                        pd->defaults_allow_any = POLKIT_RESULT_NO;
                        pd->defaults_allow_inactive = POLKIT_RESULT_NO;
                        pd->defaults_allow_active = POLKIT_RESULT_NO;
                } else if (strcmp (el, "vendor") == 0 && num_attr == 0) {
                        state = STATE_IN_POLICY_VENDOR;
                } else if (strcmp (el, "vendor_url") == 0 && num_attr == 0) {
                        state = STATE_IN_POLICY_VENDOR_URL;
                } else if (strcmp (el, "icon_name") == 0 && num_attr == 0) {
                        state = STATE_IN_POLICY_ICON_NAME;
                }
                break;
        case STATE_IN_ACTION:
                if (strcmp (el, "defaults") == 0) {
                        state = STATE_IN_DEFAULTS;
                } else if (strcmp (el, "description") == 0) {
                        if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0) {
                                pd->elem_lang = kit_strdup (attr[1]);
                                if (pd->elem_lang == NULL)
                                        goto oom;
                        }
                        state = STATE_IN_ACTION_DESCRIPTION;
                } else if (strcmp (el, "message") == 0) {
                        if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0) {
                                pd->elem_lang = kit_strdup (attr[1]);
                                if (pd->elem_lang == NULL)
                                        goto oom;
                        }
                        state = STATE_IN_ACTION_MESSAGE;
                } else if (strcmp (el, "vendor") == 0 && num_attr == 0) {
                        state = STATE_IN_ACTION_VENDOR;
                } else if (strcmp (el, "vendor_url") == 0 && num_attr == 0) {
                        state = STATE_IN_ACTION_VENDOR_URL;
                } else if (strcmp (el, "icon_name") == 0 && num_attr == 0) {
                        state = STATE_IN_ACTION_ICON_NAME;
                } else if (strcmp (el, "annotate") == 0) {
                        if (num_attr != 2 || strcmp (attr[0], "key") != 0)
                                goto error;
                        state = STATE_IN_ANNOTATE;

                        kit_free (pd->annotate_key);
                        pd->annotate_key = kit_strdup (attr[1]);
                        if (pd->annotate_key == NULL)
                                goto oom;
                }
                break;
        case STATE_IN_DEFAULTS:
                if (strcmp (el, "allow_any") == 0)
                        state = STATE_IN_DEFAULTS_ALLOW_ANY;
                else if (strcmp (el, "allow_inactive") == 0)
                        state = STATE_IN_DEFAULTS_ALLOW_INACTIVE;
                else if (strcmp (el, "allow_active") == 0)
                        state = STATE_IN_DEFAULTS_ALLOW_ACTIVE;
                break;
        default:
                break;
        }

        if (state == STATE_NONE) {
                //kit_warning ("skipping unknown tag <%s> at line %d of %s", 
                //             el, (int) XML_GetCurrentLineNumber (pd->parser), pd->path);
                state = STATE_UNKNOWN_TAG;
        }

        pd->state = state;
        pd->state_stack[pd->stack_depth] = pd->state;
        pd->stack_depth++;
        return;
oom:
        pd->is_oom = TRUE;
error:
        XML_StopParser (pd->parser, FALSE);
}

static polkit_bool_t
_validate_icon_name (const char *icon_name)
{
        unsigned int n;
        polkit_bool_t ret;
        size_t len;

        ret = FALSE;

        len = strlen (icon_name);

        /* check for common suffixes */
        if (kit_str_has_suffix (icon_name, ".png"))
                goto out;
        if (kit_str_has_suffix (icon_name, ".jpg"))
                goto out;

        /* icon name cannot be a path */
        for (n = 0; n < len; n++) {
                if (icon_name [n] == '/') {
                        goto out;
                }
        }

        ret = TRUE;

out:
        return ret;
}

static void
_cdata (void *data, const char *s, int len)
{
        char *str;
        ParserData *pd = data;

        str = kit_strndup (s, len);
        if (str == NULL)
                goto oom;

        switch (pd->state) {

        case STATE_IN_ACTION_DESCRIPTION:
                if (pd->elem_lang == NULL) {
                        kit_free (pd->policy_description_nolang);
                        pd->policy_description_nolang = str;
                        str = NULL;
                } else {
                        if (!kit_hash_insert (pd->policy_descriptions, pd->elem_lang, str))
                                goto oom;
                }
                break;

        case STATE_IN_ACTION_MESSAGE:
                if (pd->elem_lang == NULL) {
                        kit_free (pd->policy_message_nolang);
                        pd->policy_message_nolang = str;
                        str = NULL;
                } else {
                        if (!kit_hash_insert (pd->policy_messages, pd->elem_lang, str))
                                goto oom;
                }
                break;

        case STATE_IN_POLICY_VENDOR:
                kit_free (pd->global_vendor);
                pd->global_vendor = str;
                str = NULL;
                break;

        case STATE_IN_POLICY_VENDOR_URL:
                kit_free (pd->global_vendor_url);
                pd->global_vendor_url = str;
                str = NULL;
                break;

        case STATE_IN_POLICY_ICON_NAME:
                if (! _validate_icon_name (str)) {
                        kit_warning ("Icon name '%s' is invalid", str);
                        goto error;
                }

                kit_free (pd->global_icon_name);
                pd->global_icon_name = str;
                str = NULL;
                break;

        case STATE_IN_ACTION_VENDOR:
                kit_free (pd->vendor);
                pd->vendor = str;
                str = NULL;
                break;

        case STATE_IN_ACTION_VENDOR_URL:
                kit_free (pd->vendor_url);
                pd->vendor_url = str;
                str = NULL;
                break;

        case STATE_IN_ACTION_ICON_NAME:
                if (! _validate_icon_name (str)) {
                        kit_warning ("Icon name '%s' is invalid", str);
                        goto error;
                }

                kit_free (pd->icon_name);
                pd->icon_name = str;
                str = NULL;
                break;

        case STATE_IN_DEFAULTS_ALLOW_ANY:
                if (!polkit_result_from_string_representation (str, &pd->defaults_allow_any))
                        goto error;
                break;
        case STATE_IN_DEFAULTS_ALLOW_INACTIVE:
                if (!polkit_result_from_string_representation (str, &pd->defaults_allow_inactive))
                        goto error;
                break;
        case STATE_IN_DEFAULTS_ALLOW_ACTIVE:
                if (!polkit_result_from_string_representation (str, &pd->defaults_allow_active))
                        goto error;
                break;

        case STATE_IN_ANNOTATE:
                if (pd->annotations == NULL) {
                        pd->annotations = kit_hash_new (kit_hash_str_hash_func, 
                                                        kit_hash_str_equal_func, 
                                                        kit_hash_str_copy, kit_hash_str_copy,
                                                        kit_free, kit_free);
                        if (pd->annotations == NULL)
                                goto oom;
                }
                if (!kit_hash_insert (pd->annotations, pd->annotate_key, str))
                        goto oom;
                break;

        default:
                break;
        }
        kit_free (str);
        return;
oom:
        pd->is_oom = TRUE;
error:
        kit_free (str);
        XML_StopParser (pd->parser, FALSE);
}

/**
 * _localize:
 * @translations: a mapping from xml:lang to the value, e.g. 'da' -> 'Smadre', 'en_CA' -> 'Punch, Aye!'
 * @untranslated: the untranslated value, e.g. 'Punch'
 * @lang: the locale we're interested in, e.g. 'da_DK', 'da', 'en_CA', 'en_US'; basically just $LANG
 * with the encoding cut off. Maybe be NULL.
 *
 * Pick the correct translation to use.
 *
 * Returns: the localized string to use
 */
static const char *
_localize (KitHash *translations, const char *untranslated, const char *lang)
{
        const char *result;
        char lang2[256];
        int n;

        if (lang == NULL) {
                result = untranslated;
                goto out;
        }

        /* first see if we have the translation */
        result = (const char *) kit_hash_lookup (translations, (void *) lang, NULL);
        if (result != NULL)
                goto out;

        /* we could have a translation for 'da' but lang=='da_DK'; cut off the last part and try again */
        strncpy (lang2, lang, sizeof (lang2));
        for (n = 0; lang2[n] != '\0'; n++) {
                if (lang2[n] == '_') {
                        lang2[n] = '\0';
                        break;
                }
        }
        result = (const char *) kit_hash_lookup (translations, (void *) lang2, NULL);
        if (result != NULL)
                goto out;

        /* fall back to untranslated */
        result = untranslated;
out:
        return result;
}

static void
_end (void *data, const char *el)
{
        ParserData *pd = data;

        kit_free (pd->elem_lang);
        pd->elem_lang = NULL;

        switch (pd->state) {
        case STATE_IN_ACTION:
        {
                const char *policy_description;
                const char *policy_message;
                PolKitActionDescription *pfe;
                char *vendor;
                char *vendor_url;
                char *icon_name;

                vendor = pd->vendor;
                if (vendor == NULL)
                        vendor = pd->global_vendor;

                vendor_url = pd->vendor_url;
                if (vendor_url == NULL)
                        vendor_url = pd->global_vendor_url;

                icon_name = pd->icon_name;
                if (icon_name == NULL)
                        icon_name = pd->global_icon_name;

                /* NOTE: caller takes ownership of the annotations object */
                pfe = _polkit_action_description_new (pd->action_id, 
                                                     vendor,
                                                     vendor_url,
                                                     icon_name,
                                                     pd->defaults_allow_any,
                                                     pd->defaults_allow_inactive,
                                                     pd->defaults_allow_active,
                                                     pd->annotations);
                if (pfe == NULL)
                        goto oom;
                pd->annotations = NULL;

                policy_description = _localize (pd->policy_descriptions, pd->policy_description_nolang, pd->lang);
                policy_message = _localize (pd->policy_messages, pd->policy_message_nolang, pd->lang);

                if (!_polkit_action_description_set_descriptions (pfe,
                                                                  policy_description,
                                                                  policy_message)) {
                        polkit_action_description_unref (pfe);
                        goto oom;
                }

                if (pd->cb (pfe, pd->user_data)) {
                        /* TODO: short-circuit */
                }

                /* and now throw it all away! (eh, don't worry, the user have probably reffed it!) */
                polkit_action_description_unref (pfe);
                break;
        }
        default:
                break;
        }

        --pd->stack_depth;
        if (pd->stack_depth < 0 || pd->stack_depth >= PARSER_MAX_DEPTH) {
                polkit_debug ("reached max depth?");
                goto error;
        }
        if (pd->stack_depth > 0)
                pd->state = pd->state_stack[pd->stack_depth - 1];
        else
                pd->state = STATE_NONE;

        return;
oom:
        pd->is_oom = 1;
error:
        XML_StopParser (pd->parser, FALSE);
}


/**
 * polkit_action_description_get_from_file:
 * @path: path to file, e.g. <literal>/usr/share/polkit-1/actions/org.freedesktop.policykit.policy</literal>
 * @cb: callback function
 * @user_data: user data
 * @error: return location for error
 *
 * Load a .policy file and iterate over all entries.
 *
 * Returns: #TRUE if @cb short-circuited the iteration. If there was
 * an error parsing @file, then @error will be set.
 **/
polkit_bool_t
polkit_action_description_get_from_file (const char                         *path,
                                         PolKitActionDescriptionForeachFunc  cb,
                                         void                               *user_data,
                                         PolKitError                       **error)
{
        ParserData pd;
        int xml_res;
        char *lang;
	char *buf;
	size_t buflen;

        buf = NULL;

        /* clear parser data */
        memset (&pd, 0, sizeof (ParserData));

        if (!kit_str_has_suffix (path, ".policy")) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Policy files must have extension .policy; file '%s' doesn't", path);
                goto error;
        }

	if (!kit_file_get_contents (path, &buf, &buflen)) {
                if (errno == ENOMEM) {
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY,
                                                "Cannot load PolicyKit policy file at '%s': %s",
                                                path,
                                                "No memory for parser");
                } else {
                        polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                                "Cannot load PolicyKit policy file at '%s': %m",
                                                path);
                }
		goto error;
        }

        pd.path = path;
        pd.cb = cb;
        pd.user_data = user_data;

/* #ifdef POLKIT_BUILD_TESTS
   TODO: expat appears to leak on certain OOM paths
*/
#if 0
        XML_Memory_Handling_Suite memsuite = {p_malloc, p_realloc, kit_free};
        pd.parser = XML_ParserCreate_MM (NULL, &memsuite, NULL);
#else
        pd.parser = XML_ParserCreate (NULL);
#endif
        pd.stack_depth = 0;
        if (pd.parser == NULL) {
                polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY,
                                        "Cannot load PolicyKit policy file at '%s': %s",
                                        path,
                                        "No memory for parser");
                goto error;
        }
	XML_SetUserData (pd.parser, &pd);
	XML_SetElementHandler (pd.parser, _start, _end);
	XML_SetCharacterDataHandler (pd.parser, _cdata);

        /* init parser data */
        pd.state = STATE_NONE;
        lang = getenv ("LANG");
        if (lang != NULL) {
                int n;
                pd.lang = kit_strdup (lang);
                if (pd.lang == NULL) {
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY,
                                                "Cannot load PolicyKit policy file at '%s': No memory for lang",
                                                path);
                        goto error;
                }
                for (n = 0; pd.lang[n] != '\0'; n++) {
                        if (pd.lang[n] == '.') {
                                pd.lang[n] = '\0';
                                break;
                        }
                }
        }

        xml_res = XML_Parse (pd.parser, buf, buflen, 1);

	if (xml_res == 0) {
                if (XML_GetErrorCode (pd.parser) == XML_ERROR_NO_MEMORY) {
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY,
                                                "Out of memory parsing %s",
                                                path);
                } else if (pd.is_oom) {
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY,
                                                "Out of memory parsing %s",
                                                path);
                } else {
                        polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                                "%s:%d: parse error: %s",
                                                path, 
                                                (int) XML_GetCurrentLineNumber (pd.parser),
                                                XML_ErrorString (XML_GetErrorCode (pd.parser)));
                }
		XML_ParserFree (pd.parser);
		goto error;
	}

	XML_ParserFree (pd.parser);
	kit_free (buf);
        pd_unref_data (&pd);

        return FALSE; /* TODO */
error:
        pd_unref_data (&pd);
        kit_free (buf);
        return FALSE; /* TODO */
}

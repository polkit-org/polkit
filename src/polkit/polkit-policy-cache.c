/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-cache.c : policy cache
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <dirent.h>

#include "polkit-debug.h"
#include "polkit-policy-file.h"
#include "polkit-policy-cache.h"
#include "polkit-private.h"
#include "polkit-test.h"

/**
 * SECTION:polkit-policy-cache
 * @title: Policy Cache
 * @short_description: Holds the actions defined on the system.
 *
 * This class is used to hold all policy objects (stemming from policy
 * files) and provide look-up functions.
 **/

/**
 * PolKitPolicyCache:
 *
 * Instances of this class are used to hold all policy objects
 * (stemming from policy files) and provide look-up functions.
 **/
struct _PolKitPolicyCache
{
        int refcount;

        KitList *priv_entries;
};


static polkit_bool_t
_prepend_entry (PolKitPolicyFile       *policy_file,
               PolKitPolicyFileEntry  *policy_file_entry,
               void                   *user_data)
{
        KitList *l;
        PolKitPolicyCache *policy_cache = user_data;

        polkit_policy_file_entry_ref (policy_file_entry);
        l = kit_list_prepend (policy_cache->priv_entries, policy_file_entry);
        if (l == NULL) {
                polkit_policy_file_entry_unref (policy_file_entry);
                goto oom;
        }
        policy_cache->priv_entries = l;
        return FALSE;
oom:
        return TRUE;
}

PolKitPolicyCache *
_polkit_policy_cache_new (const char *dirname, polkit_bool_t load_descriptions, PolKitError **error)
{
        DIR *dir;
        struct dirent64 *d;
        PolKitPolicyCache *pc;

        dir = NULL;

        pc = kit_new0 (PolKitPolicyCache, 1);
        if (pc == NULL) {
                polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY, "Out of memory");
                goto out;
        }

        pc->refcount = 1;

        dir = opendir (dirname);
        if (dir == NULL) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Cannot load policy files from directory %s: %m",
                                        dirname);
                goto out;
        }

        while ((d = readdir64 (dir)) != NULL) {
                char *path;
                PolKitPolicyFile *pf;
                PolKitError *pk_error;
                size_t name_len;
                char *filename;
                static const char suffix[] = ".policy";

                if (d->d_type != DT_REG)
                        continue;

                filename = d->d_name;
                name_len = strlen (filename);
                if (name_len < sizeof (suffix) || strcmp ((filename + name_len - sizeof (suffix) + 1), suffix) != 0)
                        continue;

                path = kit_strdup_printf ("%s/%s", dirname, filename);
                if (path == NULL) {
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY, "Out of memory");
                        goto out;
                }

                _pk_debug ("Loading %s", path);
                pk_error = NULL;
                pf = polkit_policy_file_new (path, load_descriptions, &pk_error);
                kit_free (path);

                if (pf == NULL) {
                        if (polkit_error_get_error_code (pk_error) == POLKIT_ERROR_OUT_OF_MEMORY) {
                                if (error != NULL)
                                        *error = pk_error;
                                else
                                        polkit_error_free (pk_error);
                                goto out;
                        }

                        //kit_warning ("libpolkit: ignoring malformed policy file: %s", 
                        //             polkit_error_get_error_message (pk_error));
                        polkit_error_free (pk_error);
                        continue;
                }

                /* steal entries */
                if (polkit_policy_file_entry_foreach (pf, _prepend_entry, pc)) {
                        /* OOM failure */
                        polkit_policy_file_unref (pf);
                        polkit_error_set_error (error, POLKIT_ERROR_OUT_OF_MEMORY, "Out of memory");
                        goto out;
                }
                polkit_policy_file_unref (pf);
        }
        closedir (dir);

        return pc;
out:
        if (dir != NULL)
                closedir(dir);

        if (pc != NULL)
                polkit_policy_cache_unref (pc);
        return NULL;
}

/**
 * polkit_policy_cache_ref:
 * @policy_cache: the policy cache object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyCache *
polkit_policy_cache_ref (PolKitPolicyCache *policy_cache)
{
        kit_return_val_if_fail (policy_cache != NULL, policy_cache);
        policy_cache->refcount++;
        return policy_cache;
}

/**
 * polkit_policy_cache_unref:
 * @policy_cache: the policy cache object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_policy_cache_unref (PolKitPolicyCache *policy_cache)
{
        KitList *i;

        kit_return_if_fail (policy_cache != NULL);
        policy_cache->refcount--;
        if (policy_cache->refcount > 0) 
                return;

        for (i = policy_cache->priv_entries; i != NULL; i = i->next) {
                PolKitPolicyFileEntry *pfe = i->data;
                polkit_policy_file_entry_unref (pfe);
        }
        if (policy_cache->priv_entries != NULL)
                kit_list_free (policy_cache->priv_entries);

        kit_free (policy_cache);
}

/**
 * polkit_policy_cache_debug:
 * @policy_cache: the cache
 * 
 * Print debug information about object
 **/
void
polkit_policy_cache_debug (PolKitPolicyCache *policy_cache)
{
        KitList *i;
        kit_return_if_fail (policy_cache != NULL);

        _pk_debug ("PolKitPolicyCache: refcount=%d num_entries=%d ...", 
                   policy_cache->refcount,
                   policy_cache->priv_entries == NULL ? 0 : kit_list_length (policy_cache->priv_entries));

        for (i = policy_cache->priv_entries; i != NULL; i = i->next) {
                PolKitPolicyFileEntry *pfe = i->data;
                polkit_policy_file_entry_debug (pfe);
        }
}

/**
 * polkit_policy_cache_get_entry_by_id:
 * @policy_cache: the cache
 * @action_id: the action identifier
 * 
 * Given a action identifier, find the object describing the
 * definition of the policy; e.g. data stemming from files in
 * /usr/share/PolicyKit/policy.
 * 
 * Returns: A #PolKitPolicyFileEntry entry on sucess; otherwise
 * #NULL if the action wasn't identified. Caller shall not unref
 * this object.
 **/
PolKitPolicyFileEntry* 
polkit_policy_cache_get_entry_by_id (PolKitPolicyCache *policy_cache, const char *action_id)
{
        KitList *i;
        PolKitPolicyFileEntry *pfe;

        kit_return_val_if_fail (policy_cache != NULL, NULL);
        kit_return_val_if_fail (action_id != NULL, NULL);

        pfe = NULL;

        for (i = policy_cache->priv_entries; i != NULL; i = i->next) {
                pfe = i->data;
                if (strcmp (polkit_policy_file_entry_get_id (pfe), action_id) == 0) {
                        goto out;
                }
        }
        pfe = NULL;

        if (pfe == NULL) {
                /* the authdb backend may want to synthesize pfe's */
                pfe = _polkit_authorization_db_pfe_get_by_id (policy_cache, action_id);
        }

out:
        return pfe;        
}

/**
 * polkit_policy_cache_get_entry:
 * @policy_cache: the cache
 * @action: the action
 * 
 * Given a action, find the object describing the definition of the
 * policy; e.g. data stemming from files in
 * /usr/share/PolicyKit/policy.
 * 
 * Returns: A #PolKitPolicyFileEntry entry on sucess; otherwise
 * #NULL if the action wasn't identified. Caller shall not unref
 * this object.
 **/
PolKitPolicyFileEntry* 
polkit_policy_cache_get_entry (PolKitPolicyCache *policy_cache,
                                  PolKitAction      *action)
{
        char *action_id;
        PolKitPolicyFileEntry *pfe;

        /* I'm sure it would be easy to make this O(1)... */

        kit_return_val_if_fail (policy_cache != NULL, NULL);
        kit_return_val_if_fail (action != NULL, NULL);

        pfe = NULL;

        if (!polkit_action_get_action_id (action, &action_id))
                goto out;

        pfe = polkit_policy_cache_get_entry_by_id (policy_cache, action_id);

out:
        return pfe;
}

/**
 * polkit_policy_cache_foreach:
 * @policy_cache: the policy cache
 * @callback: callback function
 * @user_data: user data to pass to callback function
 * 
 * Visit all entries in the policy cache.
 *
 * Returns: #TRUE only if iteration was short-circuited
 **/
polkit_bool_t
polkit_policy_cache_foreach (PolKitPolicyCache *policy_cache, 
                             PolKitPolicyCacheForeachFunc callback,
                             void *user_data)
{
        KitList *i;
        PolKitPolicyFileEntry *pfe;

        kit_return_val_if_fail (policy_cache != NULL, FALSE);
        kit_return_val_if_fail (callback != NULL, FALSE);

        for (i = policy_cache->priv_entries; i != NULL; i = i->next) {
                pfe = i->data;
                if (callback (policy_cache, pfe, user_data))
                        return TRUE;
        }

        /* the authdb backend may also want to return synthesized pfe's */
        return _polkit_authorization_db_pfe_foreach (policy_cache,
                                                     callback,
                                                     user_data);
}

/**
 * polkit_policy_cache_get_entry_by_annotation:
 * @policy_cache: the policy cache
 * @annotation_key: the key to check for
 * @annotation_value: the value to check for
 *
 * Find the first policy file entry where a given annotation matches a
 * given value. Note that there is nothing preventing the existence of
 * multiple policy file entries matching this criteria; it would
 * however be a packaging bug if this situation occured.
 *
 * Returns: The first #PolKitPolicyFileEntry matching the search
 * criteria. The caller shall not unref this object. Returns #NULL if
 * there are no policy file entries matching the search criteria.
 *
 * Since: 0.7
 */
PolKitPolicyFileEntry* 
polkit_policy_cache_get_entry_by_annotation (PolKitPolicyCache *policy_cache, 
                                             const char *annotation_key,
                                             const char *annotation_value)
{
        KitList *i;

        kit_return_val_if_fail (policy_cache != NULL, NULL);
        kit_return_val_if_fail (annotation_key != NULL, NULL);
        kit_return_val_if_fail (annotation_value != NULL, NULL);

        for (i = policy_cache->priv_entries; i != NULL; i = i->next) {
                const char *value;
                PolKitPolicyFileEntry *pfe = i->data;

                value = polkit_policy_file_entry_get_annotation (pfe, annotation_key);
                if (value == NULL)
                        continue;

                if (strcmp (annotation_value, value) == 0) {
                        return pfe;
                }
        }

        return NULL;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_test_count (PolKitPolicyCache *pc, PolKitPolicyFileEntry *pfe, void *user_data)
{
        int *counter = (int *) user_data;
        const char *action_id;

        action_id = polkit_policy_file_entry_get_id (pfe);
        if (action_id != NULL && (strcmp (action_id, "org.example.valid1") == 0 ||
                                  strcmp (action_id, "org.example.valid2") == 0 ||
                                  strcmp (action_id, "org.example.valid2b") == 0 ||
                                  strcmp (action_id, "org.example.valid3") == 0 ||
                                  strcmp (action_id, "org.example.valid3b") == 0 ||
                                  strcmp (action_id, "org.example.valid4") == 0)) {
                *counter += 1;
        }
                    
        return FALSE;
}

static polkit_bool_t
_test_short_circuit (PolKitPolicyCache *pc, PolKitPolicyFileEntry *pfe, void *user_data)
{
        int *counter = (int *) user_data;
        *counter += 1;
        return TRUE;
}

static polkit_bool_t
_run_test (void)
{
        PolKitError *error;
        PolKitPolicyCache *pc;
        PolKitPolicyFileEntry *pfe;
        PolKitAction *a;
        int counter;

        error = NULL;
        kit_assert (_polkit_policy_cache_new (TEST_DATA_DIR "/non-existant", TRUE, &error) == NULL);
        kit_assert (polkit_error_is_set (error) && 
                  (polkit_error_get_error_code (error) == POLKIT_ERROR_POLICY_FILE_INVALID ||
                   polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY));
        polkit_error_free (error);

        error = NULL;
        if ((pc = _polkit_policy_cache_new (TEST_DATA_DIR "/invalid", TRUE, &error)) == NULL) {
                kit_assert (polkit_error_is_set (error) && 
                          polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
        } else {
                polkit_policy_cache_unref (pc);
        }

        error = NULL;
        if ((pc = _polkit_policy_cache_new (TEST_DATA_DIR "/valid", TRUE, &error)) == NULL) {
                kit_assert (polkit_error_is_set (error) && 
                          polkit_error_get_error_code (error) == POLKIT_ERROR_OUT_OF_MEMORY);
                polkit_error_free (error);
                goto out;
        }

        kit_assert (polkit_policy_cache_get_entry_by_id (pc, "org.example.valid1") != NULL);
        kit_assert (polkit_policy_cache_get_entry_by_id (pc, "org.example.non-existant") == NULL);

        pfe = polkit_policy_cache_get_entry_by_annotation (pc, "the.key1", "Some Value 1");
        kit_assert (pfe != NULL && strcmp (polkit_policy_file_entry_get_id (pfe), "org.example.valid2") == 0);
        pfe = polkit_policy_cache_get_entry_by_annotation (pc, "the.key2", "Some Value 2");
        kit_assert (pfe != NULL && strcmp (polkit_policy_file_entry_get_id (pfe), "org.example.valid2") == 0);
        pfe = polkit_policy_cache_get_entry_by_annotation (pc, "the.key1", "Some Value 1b");
        kit_assert (pfe != NULL && strcmp (polkit_policy_file_entry_get_id (pfe), "org.example.valid2b") == 0);
        pfe = polkit_policy_cache_get_entry_by_annotation (pc, "the.key1", "NON-EXISTANT VALUE");
        kit_assert (pfe == NULL);
        pfe = polkit_policy_cache_get_entry_by_annotation (pc, "NON_EXISTANT KEY", "NON-EXISTANT VALUE");
        kit_assert (pfe == NULL);

        if ((a = polkit_action_new ()) != NULL) {
                pfe = polkit_policy_cache_get_entry (pc, a);
                kit_assert (pfe == NULL);
                if (polkit_action_set_action_id (a, "org.example.valid1")) {
                        pfe = polkit_policy_cache_get_entry (pc, a);
                        kit_assert (pfe != NULL && strcmp (polkit_policy_file_entry_get_id (pfe), "org.example.valid1") == 0);
                }
                if (polkit_action_set_action_id (a, "org.example.non-existant")) {
                        pfe = polkit_policy_cache_get_entry (pc, a);
                        kit_assert (pfe == NULL);
                }

                polkit_action_unref (a);
        }

        counter = 0;
        polkit_policy_cache_foreach (pc, _test_count, &counter);
        kit_assert (counter == 6);

        counter = 0;
        polkit_policy_cache_foreach (pc, _test_short_circuit, &counter);
        kit_assert (counter == 1);

        polkit_policy_cache_debug (pc);
        polkit_policy_cache_ref (pc);
        polkit_policy_cache_unref (pc);
        polkit_policy_cache_unref (pc);
out:
        return TRUE;
}

KitTest _test_policy_cache = {
        "polkit_policy_cache",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

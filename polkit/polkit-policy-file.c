/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file.c : policy files
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>

#include <expat.h>

#include <glib.h>
#include "polkit-error.h"
#include "polkit-result.h"
#include "polkit-policy-file.h"
#include "polkit-policy-file-entry.h"
#include "polkit-debug.h"

/**
 * SECTION:polkit-policy-file
 * @title: Policy Definition Files
 * @short_description: Represents a set of declared actions.
 *
 * This class is used to represent a policy files.
 **/

/**
 * PolKitPolicyFile:
 *
 * Objects of this class are used to record information about a
 * policy file.
 **/
struct PolKitPolicyFile
{
        int refcount;
        GSList *entries;
};

extern PolKitPolicyFileEntry *_polkit_policy_file_entry_new   (const char *action_id, 
                                                               PolKitResult defaults_allow_inactive,
                                                               PolKitResult defaults_allow_active,
                                                               GHashTable *annotations);

enum {
        STATE_NONE,
        STATE_IN_POLICY_CONFIG,
        STATE_IN_ACTION,
        STATE_IN_ACTION_DESCRIPTION,
        STATE_IN_ACTION_MESSAGE,
        STATE_IN_DEFAULTS,
        STATE_IN_DEFAULTS_ALLOW_INACTIVE,
        STATE_IN_DEFAULTS_ALLOW_ACTIVE,
        STATE_IN_ANNOTATE
};

typedef struct {
        XML_Parser parser;
        int state;

        char *action_id;

        PolKitResult defaults_allow_inactive;
        PolKitResult defaults_allow_active;

        PolKitPolicyFile *pf;

        polkit_bool_t load_descriptions;

        GHashTable *policy_descriptions;
        GHashTable *policy_messages;

        char *policy_description_nolang;
        char *policy_message_nolang;

        /* the language according to $LANG (e.g. en_US, da_DK, fr, en_CA minus the encoding) */
        char *lang;

        /* the value of xml:lang for the thing we're reading in _cdata() */
        char *elem_lang;

        char *annotate_key;
        GHashTable *annotations;
} ParserData;

static void
pd_unref_action_data (ParserData *pd)
{
        g_free (pd->action_id);
        pd->action_id = NULL;
        g_free (pd->policy_description_nolang);
        pd->policy_description_nolang = NULL;
        g_free (pd->policy_message_nolang);
        pd->policy_message_nolang = NULL;
        if (pd->policy_descriptions != NULL) {
                g_hash_table_destroy (pd->policy_descriptions);
                pd->policy_descriptions = NULL;
        }
        if (pd->policy_messages != NULL) {
                g_hash_table_destroy (pd->policy_messages);
                pd->policy_messages = NULL;
        }
        g_free (pd->annotate_key);
        pd->annotate_key = NULL;
        if (pd->annotations != NULL) {
                g_hash_table_destroy (pd->annotations);
                pd->annotations = NULL;
        }
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
                        pd->action_id = g_strdup (attr[1]);
                        pd->policy_descriptions = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
                        pd->policy_messages = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

                        /* initialize defaults */
                        pd->defaults_allow_inactive = POLKIT_RESULT_NO;
                        pd->defaults_allow_active = POLKIT_RESULT_NO;
                }
                break;
        case STATE_IN_ACTION:
                if (strcmp (el, "defaults") == 0) {
                        state = STATE_IN_DEFAULTS;
                } else if (strcmp (el, "description") == 0) {
                        if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0) {
                                pd->elem_lang = g_strdup (attr[1]);
                        }
                        state = STATE_IN_ACTION_DESCRIPTION;
                } else if (strcmp (el, "message") == 0) {
                        if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0) {
                                pd->elem_lang = g_strdup (attr[1]);
                        }
                        state = STATE_IN_ACTION_MESSAGE;
                } else if (strcmp (el, "annotate") == 0) {
                        if (num_attr != 2 || strcmp (attr[0], "key") != 0)
                                goto error;
                        state = STATE_IN_ANNOTATE;

                        g_free (pd->annotate_key);
                        pd->annotate_key = g_strdup (attr[1]);
                }
                break;
        case STATE_IN_ACTION_DESCRIPTION:
                break;
        case STATE_IN_ACTION_MESSAGE:
                break;
        case STATE_IN_DEFAULTS:
                if (strcmp (el, "allow_inactive") == 0)
                        state = STATE_IN_DEFAULTS_ALLOW_INACTIVE;
                else if (strcmp (el, "allow_active") == 0)
                        state = STATE_IN_DEFAULTS_ALLOW_ACTIVE;
                break;
        case STATE_IN_DEFAULTS_ALLOW_INACTIVE:
                break;
        case STATE_IN_DEFAULTS_ALLOW_ACTIVE:
                break;
        case STATE_IN_ANNOTATE:
                break;
        default:
                break;
        }

        if (state == STATE_NONE)
                goto error;

        pd->state = state;

        return;
error:
        XML_StopParser (pd->parser, FALSE);
}

static void
_cdata (void *data, const char *s, int len)
{
        char *str;
        ParserData *pd = data;

        str = g_strndup (s, len);
        switch (pd->state) {

        case STATE_IN_ACTION_DESCRIPTION:
                if (pd->load_descriptions) {
                        if (pd->elem_lang == NULL) {
                                g_free (pd->policy_description_nolang);
                                pd->policy_description_nolang = g_strdup (str);
                        } else {
                                g_hash_table_insert (pd->policy_descriptions, g_strdup (pd->elem_lang), g_strdup (str));
                        }
                }
                break;

        case STATE_IN_ACTION_MESSAGE:
                if (pd->load_descriptions) {
                        if (pd->elem_lang == NULL) {
                                g_free (pd->policy_message_nolang);
                                pd->policy_message_nolang = g_strdup (str);
                        } else {
                                g_hash_table_insert (pd->policy_messages, g_strdup (pd->elem_lang), g_strdup (str));
                        }
                }
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
                        pd->annotations = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
                }
                g_hash_table_insert (pd->annotations, g_strdup (pd->annotate_key), g_strdup (str));
                break;

        default:
                break;
        }
        g_free (str);
        return;
error:
        g_free (str);
        XML_StopParser (pd->parser, FALSE);
}


extern void _polkit_policy_file_entry_set_descriptions (PolKitPolicyFileEntry *pfe,
                                                        const char *policy_description,
                                                        const char *policy_message);

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
_localize (GHashTable *translations, const char *untranslated, const char *lang)
{
        const char *result;
        char *lang2;
        int n;

        if (lang == NULL) {
                result = untranslated;
                goto out;
        }

        /* first see if we have the translation */
        result = g_hash_table_lookup (translations, lang);
        if (result != NULL)
                goto out;

        /* we could have a translation for 'da' but lang=='da_DK'; cut off the last part and try again */
        lang2 = g_strdup (lang);
        for (n = 0; lang2[n] != '\0'; n++) {
                if (lang2[n] == '_') {
                        lang2[n] = '\0';
                        break;
                }
        }
        result = g_hash_table_lookup (translations, lang2);
        g_free (lang2);
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
        int state;
        ParserData *pd = data;

        state = STATE_NONE;

        g_free (pd->elem_lang);
        pd->elem_lang = NULL;

        switch (pd->state) {
        case STATE_NONE:
                break;
        case STATE_IN_POLICY_CONFIG:
                state = STATE_NONE;
                break;
        case STATE_IN_ACTION:
        {
                const char *policy_description;
                const char *policy_message;
                PolKitPolicyFileEntry *pfe;

                /* NOTE: caller takes ownership of the annotations object */
                pfe = _polkit_policy_file_entry_new (pd->action_id, 
                                                     pd->defaults_allow_inactive,
                                                     pd->defaults_allow_active,
                                                     pd->annotations);
                pd->annotations = NULL;

                if (pfe == NULL)
                        goto error;

                if (pd->load_descriptions) {
                        policy_description = _localize (pd->policy_descriptions, pd->policy_description_nolang, pd->lang);
                        policy_message = _localize (pd->policy_messages, pd->policy_message_nolang, pd->lang);
                } else {
                        policy_description = NULL;
                        policy_message = NULL;
                }

                if (pd->load_descriptions)
                        _polkit_policy_file_entry_set_descriptions (pfe,
                                                                    policy_description,
                                                                    policy_message);

                pd->pf->entries = g_slist_prepend (pd->pf->entries, pfe);

                state = STATE_IN_POLICY_CONFIG;
                break;
        }
        case STATE_IN_ACTION_DESCRIPTION:
                state = STATE_IN_ACTION;
                break;
        case STATE_IN_ACTION_MESSAGE:
                state = STATE_IN_ACTION;
                break;
        case STATE_IN_DEFAULTS:
                state = STATE_IN_ACTION;
                break;
        case STATE_IN_DEFAULTS_ALLOW_INACTIVE:
                state = STATE_IN_DEFAULTS;
                break;
        case STATE_IN_DEFAULTS_ALLOW_ACTIVE:
                state = STATE_IN_DEFAULTS;
                break;
        case STATE_IN_ANNOTATE:
                state = STATE_IN_ACTION;
                break;
        default:
                break;
        }

        pd->state = state;

        return;
error:
        XML_StopParser (pd->parser, FALSE);
}


/**
 * polkit_policy_file_new:
 * @path: path to file
 * @load_descriptions: whether descriptions should be loaded
 * @error: Return location for error
 * 
 * Load a policy file.
 * 
 * Returns: The new object or #NULL if error is set
 **/
PolKitPolicyFile *
polkit_policy_file_new (const char *path, polkit_bool_t load_descriptions, PolKitError **error)
{
        PolKitPolicyFile *pf;
        ParserData pd;
        int xml_res;
        char *lang;
	char *buf;
	gsize buflen;
        GError *g_error;

        pf = NULL;

        if (!g_str_has_suffix (path, ".policy")) {
                polkit_error_set_error (error, 
                                        POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Policy files must have extension .policy; file '%s' doesn't", path);
                goto error;
        }

        g_error = NULL;
	if (!g_file_get_contents (path, &buf, &buflen, &g_error)) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Cannot load PolicyKit policy file at '%s': %s",
                                        path,
                                        g_error->message);
                g_error_free (g_error);
		goto error;
        }

        /* clear parser data */
        memset (&pd, 0, sizeof (ParserData));

        pd.parser = XML_ParserCreate (NULL);
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

        pf = g_new0 (PolKitPolicyFile, 1);
        pf->refcount = 1;

        /* init parser data */
        pd.state = STATE_NONE;
        pd.pf = pf;
        pd.load_descriptions = load_descriptions;
        lang = getenv ("LANG");
        if (lang != NULL) {
                int n;
                pd.lang = g_strdup (lang);
                for (n = 0; pd.lang[n] != '\0'; n++) {
                        if (pd.lang[n] == '.') {
                                pd.lang[n] = '\0';
                                break;
                        }
                }
        }

        xml_res = XML_Parse (pd.parser, buf, buflen, 1);

	if (xml_res == 0) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "%s:%d: parse error: %s",
                                        path, 
                                        (int) XML_GetCurrentLineNumber (pd.parser),
                                        XML_ErrorString (XML_GetErrorCode (pd.parser)));

		XML_ParserFree (pd.parser);
		g_free (buf);
		goto error;
	}
	XML_ParserFree (pd.parser);
	g_free (buf);
        pd_unref_action_data (&pd);
        return pf;
error:
        if (pf != NULL)
                polkit_policy_file_unref (pf);
        pd_unref_action_data (&pd);
        return NULL;
}

/**
 * polkit_policy_file_ref:
 * @policy_file: the policy file object
 * 
 * Increase reference count.
 * 
 * Returns: the object
 **/
PolKitPolicyFile *
polkit_policy_file_ref (PolKitPolicyFile *policy_file)
{
        g_return_val_if_fail (policy_file != NULL, policy_file);
        policy_file->refcount++;
        return policy_file;
}

/**
 * polkit_policy_file_unref:
 * @policy_file: the policy file object
 * 
 * Decreases the reference count of the object. If it becomes zero,
 * the object is freed. Before freeing, reference counts on embedded
 * objects are decresed by one.
 **/
void
polkit_policy_file_unref (PolKitPolicyFile *policy_file)
{
        GSList *i;
        g_return_if_fail (policy_file != NULL);
        policy_file->refcount--;
        if (policy_file->refcount > 0) 
                return;
        for (i = policy_file->entries; i != NULL; i = g_slist_next (i)) {
                polkit_policy_file_entry_unref (i->data);
        }
        if (policy_file->entries != NULL)
                g_slist_free (policy_file->entries);
        g_free (policy_file);
}

/**
 * polkit_policy_file_entry_foreach:
 * @policy_file: the policy file object
 * @cb: callback to invoke for each entry
 * @user_data: user data
 * 
 * Visits all entries in a policy file.
 **/
void
polkit_policy_file_entry_foreach (PolKitPolicyFile                 *policy_file,
                                     PolKitPolicyFileEntryForeachFunc  cb,
                                     void                              *user_data)
{
        GSList *i;

        g_return_if_fail (policy_file != NULL);
        g_return_if_fail (cb != NULL);

        for (i = policy_file->entries; i != NULL; i = g_slist_next (i)) {
                PolKitPolicyFileEntry *pfe = i->data;
                cb (policy_file, pfe, user_data);
        }
}

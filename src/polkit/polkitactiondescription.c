/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include "config.h"
#include <string.h>
#include "polkitactiondescription.h"

/**
 * SECTION:polkitactiondescription
 * @short_description: Description of an action
 * @include: polkit/polkit.h
 *
 * Describes an action.
 */

/*--------------------------------------------------------------------------------------------------------------*/

struct _PolkitActionDescriptionPrivate
{
  char *action_id;
  GIcon *icon;
  char *description;
  char *message;
  char *vendor_name;
  char *vendor_url;
  GHashTable *annotations;
};

enum {
  PROP_0,
  PROP_ACTION_ID,
  PROP_ICON,
  PROP_DESCRIPTION,
  PROP_MESSAGE,
  PROP_VENDOR_NAME,
  PROP_VENDOR_URL,
  PROP_ANNOTATIONS,
};

G_DEFINE_TYPE (PolkitActionDescription, polkit_action_description, G_TYPE_OBJECT)

#define POLKIT_ACTION_DESCRIPTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), POLKIT_TYPE_ACTION_DESCRIPTION, PolkitActionDescriptionPrivate))

static void
polkit_action_description_get_property (GObject    *object,
                                        guint       prop_id,
                                        GValue     *value,
                                        GParamSpec *pspec)
{
  PolkitActionDescription *action_description = POLKIT_ACTION_DESCRIPTION (object);

  switch (prop_id)
    {
    case PROP_ACTION_ID:
      g_value_set_string (value, action_description->priv->action_id);
      break;

    case PROP_ICON:
      g_value_set_object (value, action_description->priv->icon);
      break;

    case PROP_DESCRIPTION:
      g_value_set_string (value, action_description->priv->description);
      break;

    case PROP_MESSAGE:
      g_value_set_string (value, action_description->priv->message);
      break;

    case PROP_VENDOR_NAME:
      g_value_set_string (value, action_description->priv->vendor_name);
      break;

    case PROP_VENDOR_URL:
      g_value_set_string (value, action_description->priv->vendor_url);
      break;

    case PROP_ANNOTATIONS:
      g_value_set_boxed (value, action_description->priv->annotations);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_action_description_init (PolkitActionDescription *action_description)
{
  action_description->priv = POLKIT_ACTION_DESCRIPTION_GET_PRIVATE (action_description);
  action_description->priv->annotations = g_hash_table_new_full (g_str_hash,
                                                                 g_str_equal,
                                                                 g_free,
                                                                 g_free);
}

static void
polkit_action_description_finalize (GObject *object)
{
  PolkitActionDescription *action_description;

  g_return_if_fail (object != NULL);
  g_return_if_fail (POLKIT_IS_ACTION_DESCRIPTION (object));

  action_description = POLKIT_ACTION_DESCRIPTION (object);

  if (action_description->priv->icon != NULL)
    g_object_unref (action_description->priv->icon);
  g_free (action_description->priv->action_id);
  g_free (action_description->priv->description);
  g_free (action_description->priv->message);
  g_free (action_description->priv->vendor_name);
  g_free (action_description->priv->vendor_url);
  g_hash_table_unref (action_description->priv->annotations);

  G_OBJECT_CLASS (polkit_action_description_parent_class)->finalize (object);
}

static void
polkit_action_description_class_init (PolkitActionDescriptionClass *klass)
{
  GObjectClass   *object_class = G_OBJECT_CLASS (klass);

  object_class->get_property = polkit_action_description_get_property;
  object_class->finalize = polkit_action_description_finalize;

  /**
   * PolkitActionDescription:action-id:
   *
   * The action id for the action being described.
   */
  g_object_class_install_property (object_class,
                                   PROP_ACTION_ID,
                                   g_param_spec_string ("action-id",
                                                        "action-id",
                                                        "The action identifier for the action",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitActionDescription:icon:
   *
   * The icon for the action being described.
   */
  g_object_class_install_property (object_class,
                                   PROP_ICON,
                                   g_param_spec_object ("icon",
                                                        "icon",
                                                        "The icon for the action",
                                                        G_TYPE_ICON,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitActionDescription:description:
   *
   * A localized human readable description of the action.
   */
  g_object_class_install_property (object_class,
                                   PROP_DESCRIPTION,
                                   g_param_spec_string ("description",
                                                        "description",
                                                        "Description of action",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitActionDescription:message:
   *
   * A localized human readable message to display to the user
   * when he lacks an authorization for the action.
   */
  g_object_class_install_property (object_class,
                                   PROP_MESSAGE,
                                   g_param_spec_string ("message",
                                                        "message",
                                                        "Message for the action",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitActionDescription:vendor-name:
   *
   * The name of the organization supplying the action.
   */
  g_object_class_install_property (object_class,
                                   PROP_VENDOR_NAME,
                                   g_param_spec_string ("vendor-name",
                                                        "vendor-name",
                                                        "Vendor for the action",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitActionDescription:vendor-url:
   *
   * An URL (Uniform Resource Locator) describing the action.
   */
  g_object_class_install_property (object_class,
                                   PROP_VENDOR_URL,
                                   g_param_spec_string ("vendor-url",
                                                        "vendor-url",
                                                        "Vendor URL for the action",
                                                        NULL,
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_NICK |
                                                        G_PARAM_STATIC_BLURB));

  /**
   * PolkitActionDescription:annotations:
   *
   * A set of key/value pairs giving more information about the action.
   */
  g_object_class_install_property (object_class,
                                   PROP_ANNOTATIONS,
                                   g_param_spec_boxed ("annotations",
                                                       "annotations",
                                                       "Annotations for the action",
                                                       G_TYPE_HASH_TABLE,
                                                       G_PARAM_READABLE |
                                                       G_PARAM_STATIC_NAME |
                                                       G_PARAM_STATIC_NICK |
                                                       G_PARAM_STATIC_BLURB));

  g_type_class_add_private (klass, sizeof (PolkitActionDescriptionPrivate));
}

const gchar *
polkit_action_description_get_action_id (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->priv->action_id;
}

GIcon *
polkit_action_description_get_icon (PolkitActionDescription  *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  if (action_description->priv->icon != NULL)
    return g_object_ref (action_description->priv->icon);
  return NULL;
}

const gchar *
polkit_action_description_get_description (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->priv->description;
}

const gchar *
polkit_action_description_get_message (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->priv->message;
}

const gchar *
polkit_action_description_get_vendor_name (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->priv->vendor_name;
}

const gchar *
polkit_action_description_get_vendor_url (PolkitActionDescription *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->priv->vendor_url;
}

GHashTable *
polkit_action_description_get_annotations (PolkitActionDescription  *action_description)
{
  g_return_val_if_fail (POLKIT_IS_ACTION_DESCRIPTION (action_description), NULL);
  return action_description->priv->annotations;
}

/* ---------------------------------------------------------------------------------------------------- */

#if 0
#include <expat.h> /* TODO: move to separate file */

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

        //PolKitResult defaults_allow_any;
        //PolKitResult defaults_allow_inactive;
        //PolKitResult defaults_allow_active;

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

        PolKitActionDescriptionForeachFunc cb;
        void *user_data;
} ParserData;

static void
pd_unref_action_data (ParserData *pd)
{
        g_free (pd->action_id);
        pd->action_id = NULL;

        g_free (pd->vendor);
        pd->vendor = NULL;
        g_free (pd->vendor_url);
        pd->vendor_url = NULL;
        g_free (pd->icon_name);
        pd->icon_name = NULL;

        g_free (pd->policy_description_nolang);
        pd->policy_description_nolang = NULL;
        g_free (pd->policy_message_nolang);
        pd->policy_message_nolang = NULL;
        if (pd->policy_descriptions != NULL) {
                g_hash_table_unref (pd->policy_descriptions);
                pd->policy_descriptions = NULL;
        }
        if (pd->policy_messages != NULL) {
                g_hash_table_unref (pd->policy_messages);
                pd->policy_messages = NULL;
        }
        g_free (pd->annotate_key);
        pd->annotate_key = NULL;
        if (pd->annotations != NULL) {
                g_hash_table_unref (pd->annotations);
                pd->annotations = NULL;
        }
        g_free (pd->elem_lang);
        pd->elem_lang = NULL;
}

static void
pd_unref_data (ParserData *pd)
{
        pd_unref_action_data (pd);
        g_free (pd->lang);
        pd->lang = NULL;

        g_free (pd->global_vendor);
        pd->global_vendor = NULL;
        g_free (pd->global_vendor_url);
        pd->global_vendor_url = NULL;
        g_free (pd->global_icon_name);
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

                        //if (!polkit_action_validate_id (attr[1]))
                        //        goto error;

                        pd_unref_action_data (pd);
                        pd->action_id = g_strdup (attr[1]);
                        pd->policy_descriptions = g_hash_table_new_full (g_str_hash,
                                                                         g_str_equal,
                                                                         g_free,
                                                                         g_free);
                        pd->policy_messages = g_hash_table_new_full (g_str_hash,
                                                                     g_str_equal,
                                                                     g_free,
                                                                     g_free);
                        /* initialize defaults */
                        //pd->defaults_allow_any = POLKIT_RESULT_NO;
                        //pd->defaults_allow_inactive = POLKIT_RESULT_NO;
                        //pd->defaults_allow_active = POLKIT_RESULT_NO;
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
                                pd->elem_lang = g_strdup (attr[1]);
                        }
                        state = STATE_IN_ACTION_DESCRIPTION;
                } else if (strcmp (el, "message") == 0) {
                        if (num_attr == 2 && strcmp (attr[0], "xml:lang") == 0) {
                                pd->elem_lang = g_strdup (attr[1]);
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

                        g_free (pd->annotate_key);
                        pd->annotate_key = g_strdup (attr[1]);
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
                g_warning ("skipping unknown tag <%s> at line %d of %s",
                           el, (int) XML_GetCurrentLineNumber (pd->parser), pd->path);
                state = STATE_UNKNOWN_TAG;
        }

        pd->state = state;
        pd->state_stack[pd->stack_depth] = pd->state;
        pd->stack_depth++;
        return;
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
        if (g_str_has_suffix (icon_name, ".png"))
                goto out;
        if (g_str_has_suffix (icon_name, ".jpg"))
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

        str = g_strndup (s, len);

        switch (pd->state) {

        case STATE_IN_ACTION_DESCRIPTION:
                if (pd->elem_lang == NULL) {
                        g_free (pd->policy_description_nolang);
                        pd->policy_description_nolang = str;
                        str = NULL;
                } else {
                        g_hash_table_insert (pd->policy_descriptions,
                                             g_strdup (pd->elem_lang),
                                             str);
                        str = NULL;
                }
                break;

        case STATE_IN_ACTION_MESSAGE:
                if (pd->elem_lang == NULL) {
                        g_free (pd->policy_message_nolang);
                        pd->policy_message_nolang = str;
                        str = NULL;
                } else {
                        g_hash_table_insert (pd->policy_messages,
                                             g_strdup (pd->elem_lang),
                                             str);
                        str = NULL;
                }
                break;

        case STATE_IN_POLICY_VENDOR:
                g_free (pd->global_vendor);
                pd->global_vendor = str;
                str = NULL;
                break;

        case STATE_IN_POLICY_VENDOR_URL:
                g_free (pd->global_vendor_url);
                pd->global_vendor_url = str;
                str = NULL;
                break;

        case STATE_IN_POLICY_ICON_NAME:
                if (! _validate_icon_name (str)) {
                        g_warning ("Icon name '%s' is invalid", str);
                        goto error;
                }

                g_free (pd->global_icon_name);
                pd->global_icon_name = str;
                str = NULL;
                break;

        case STATE_IN_ACTION_VENDOR:
                g_free (pd->vendor);
                pd->vendor = str;
                str = NULL;
                break;

        case STATE_IN_ACTION_VENDOR_URL:
                g_free (pd->vendor_url);
                pd->vendor_url = str;
                str = NULL;
                break;

        case STATE_IN_ACTION_ICON_NAME:
                if (! _validate_icon_name (str)) {
                        kit_warning ("Icon name '%s' is invalid", str);
                        goto error;
                }

                g_free (pd->icon_name);
                pd->icon_name = str;
                str = NULL;
                break;

        case STATE_IN_DEFAULTS_ALLOW_ANY:
                //if (!polkit_result_from_string_representation (str, &pd->defaults_allow_any))
                //        goto error;
                break;
        case STATE_IN_DEFAULTS_ALLOW_INACTIVE:
                //if (!polkit_result_from_string_representation (str, &pd->defaults_allow_inactive))
                //        goto error;
                break;
        case STATE_IN_DEFAULTS_ALLOW_ACTIVE:
                //if (!polkit_result_from_string_representation (str, &pd->defaults_allow_active))
                //        goto error;
                break;

        case STATE_IN_ANNOTATE:
                if (pd->annotations == NULL) {
                        pd->annotations = g_hash_table_new_full (g_str_hash,
                                                                 g_str_equal,
                                                                 g_free,
                                                                 g_free);
                }
                g_hash_table_insert (pd->annotations,
                                     g_strdup (pd->annotate_key),
                                     str);
                str = NULL;
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
_localize (GHashTable *translations,
           const char *untranslated,
           const char *lang)
{
        const char *result;
        char lang2[256];
        int n;

        if (lang == NULL) {
                result = untranslated;
                goto out;
        }

        /* first see if we have the translation */
        result = (const char *) g_hash_table_lookup (translations, (void *) lang);
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
        result = (const char *) kit_hash_lookup (translations, (void *) lang2);
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

        g_free (pd->elem_lang);
        pd->elem_lang = NULL;

        switch (pd->state) {
        case STATE_IN_ACTION:
        {
                const char *policy_description;
                const char *policy_message;
                //PolKitActionDescription *pfe;
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

#if 0
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
#else
                g_hash_table_unref (pd->annotations);
#endif

                pd->annotations = NULL;

                policy_description = _localize (pd->policy_descriptions, pd->policy_description_nolang, pd->lang);
                policy_message = _localize (pd->policy_messages, pd->policy_message_nolang, pd->lang);

#if 0
                if (!_polkit_action_description_set_descriptions (pfe,
                                                                  policy_description,
                                                                  policy_message)) {
                        polkit_action_description_unref (pfe);
                        goto oom;
                }
#endif

#if 0
                if (pd->cb (pfe, pd->user_data)) {
                        /* TODO: short-circuit */
                }
#endif

                /* and now throw it all away! (eh, don't worry, the user have probably reffed it!) */
                //polkit_action_description_unref (pfe);
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
        XML_Memory_Handling_Suite memsuite = {p_malloc, p_realloc, kit_free};
        pd.parser = XML_ParserCreate_MM (NULL, &memsuite, NULL);
        pd.parser = XML_ParserCreate (NULL);
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


GList *
polkit_action_description_new_from_file (GFile         *file,
                                         GCancellable  *cancellable,
                                         GError       **error)
{
        ParserData pd;
        char *contents;
        gsize contents_len;
        GList *ret;

        g_return_val_if_fail (G_IS_FILE (file), NULL);

        ret = NULL;
        contents = NULL;
        parse_context = NULL;

        parser.error = parse_error;

        parser_data = parser_data_new (&ret);

        if (!g_file_load_contents (file,
                                   cancellable,
                                   &contents,
                                   &contents_len,
                                   NULL,
                                   error)) {
                goto out;
        }

        g_warning ("need to parse '%s' %d", contents, contents_len);


        /* clear parser data */
        memset (&pd, 0, sizeof (ParserData));

        pd.parser = XML_ParserCreate (NULL);

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

 out:
        g_free (contents);
        return ret;
}

GList *
polkit_action_description_new_from_directory (GFile         *directory,
                                              GCancellable  *cancellable,
                                              GError       **error)
{
        GFileEnumerator *e;
        GError *local_error;
        GFileInfo *file_info;
        GList *ret;

        g_return_val_if_fail (G_IS_FILE (directory), NULL);

        ret = NULL;

        local_error = NULL;
        e = g_file_enumerate_children (directory,
                                       "standard::*",
                                       G_FILE_QUERY_INFO_NONE,
                                       NULL,
                                       &local_error);
        if (local_error != NULL) {
                g_propagate_error (error, local_error);
                goto out;
        }

        while ((file_info = g_file_enumerator_next_file (e, NULL, &local_error)) != NULL) {
                const char *name;
                GFile *file;

                name = g_file_info_get_name (file_info);
                /* only consider files with the right suffix */
                if (g_str_has_suffix (name, ".policy")) {
                        GList *descs_from_file;

                        file = g_file_get_child (directory, name);

                        descs_from_file = polkit_action_description_new_from_file (file,
                                                                                   cancellable,
                                                                                   &local_error);
                        if (local_error != NULL) {
                                g_list_foreach (ret, (GFunc) g_object_unref, NULL);
                                g_list_free (ret);
                                ret = NULL;

                                g_propagate_error (error, local_error);
                                goto out;
                        }

                        ret = g_list_concat (ret, descs_from_file);

                        g_object_unref (file);
                }
                g_object_unref (file_info);
        }

        if (local_error != NULL) {
                g_list_foreach (ret, (GFunc) g_object_unref, NULL);
                g_list_free (ret);
                ret = NULL;

                g_propagate_error (error, local_error);
                goto out;
        }

 out:
        if (e != NULL)
                g_object_unref (e);
        return ret;
}
#endif

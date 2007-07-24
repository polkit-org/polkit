/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-config.h : Configuration file
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
#include <sys/inotify.h>
#include <regex.h>

#include <expat.h>

#include <glib.h>
#include "polkit-config.h"
#include "polkit-debug.h"
#include "polkit-error.h"

enum {
        STATE_NONE,
        STATE_IN_CONFIG,
        STATE_IN_MATCH,
        STATE_IN_RETURN,
};

struct ConfigNode;
typedef struct ConfigNode ConfigNode;

struct PolKitConfig
{
        int refcount;
        ConfigNode *top_config_node;
};

#define PARSER_MAX_DEPTH 32

typedef struct {
        XML_Parser parser;
        int state;
        PolKitConfig *pk_config;

        int state_stack[PARSER_MAX_DEPTH];
        ConfigNode *node_stack[PARSER_MAX_DEPTH];

        int stack_depth;
} ParserData;

enum {
        NODE_TYPE_TOP,
        NODE_TYPE_MATCH,
        NODE_TYPE_RETURN,
};

enum {
        MATCH_TYPE_ACTION,
        MATCH_TYPE_USER,
};

static const char * const match_names[] = 
{
        "action",
        "user",
};

struct ConfigNode
{
        int node_type;

        union {

                struct {
                        int match_type;
                        char *data;
                        regex_t preq;
                } node_match;

                struct {
                        PolKitResult result;
                } node_return;

        } data;

        GSList *children;
};

static ConfigNode *
config_node_new (void)
{
        ConfigNode *node;
        node = g_new0 (ConfigNode, 1);
        return node;
}

static void
config_node_dump_real (ConfigNode *node, unsigned int indent)
{
        GSList *i;
        unsigned int n;
        char buf[128];

        for (n = 0; n < indent && n < sizeof (buf) - 1; n++)
                buf[n] = ' ';
        buf[n] = '\0';
        
        switch (node->node_type) {
        case NODE_TYPE_TOP:
                _pk_debug ("%sTOP", buf);
                break;
        case NODE_TYPE_MATCH:
                _pk_debug ("%sMATCH %s (%d) with '%s'", 
                           buf, 
                           match_names[node->data.node_match.match_type],
                           node->data.node_match.match_type,
                           node->data.node_match.data);
                break;
        case NODE_TYPE_RETURN:
                _pk_debug ("%sRETURN %s (%d)",
                           buf,
                           polkit_result_to_string_representation (node->data.node_return.result),
                           node->data.node_return.result);
                break;
        }

        for (i = node->children; i != NULL; i = g_slist_next (i)) {
                ConfigNode *child = i->data;
                config_node_dump_real (child, indent + 2);
        }
}

static void
config_node_dump (ConfigNode *node)
{
        
        config_node_dump_real (node, 0);
}

static void
config_node_unref (ConfigNode *node)
{
        GSList *i;

        switch (node->node_type) {
        case NODE_TYPE_TOP:
                break;
        case NODE_TYPE_MATCH:
                g_free (node->data.node_match.data);
                regfree (&(node->data.node_match.preq));
                break;
        case NODE_TYPE_RETURN:
                break;
        }

        for (i = node->children; i != NULL; i = g_slist_next (i)) {
                ConfigNode *child = i->data;
                config_node_unref (child);
        }
        g_slist_free (node->children);
        g_free (node);
}

static void
_start (void *data, const char *el, const char **attr)
{
        int state;
        int num_attr;
        ParserData *pd = data;
        ConfigNode *node;

        _pk_debug ("_start for node '%s'", el);

        for (num_attr = 0; attr[num_attr] != NULL; num_attr++)
                ;

        state = STATE_NONE;
        node = NULL;

        switch (pd->state) {
        case STATE_NONE:
                if (strcmp (el, "config") == 0) {
                        state = STATE_IN_CONFIG;
                        _pk_debug ("parsed config node");

                        if (pd->pk_config->top_config_node != NULL) {
                                _pk_debug ("Multiple config nodes?");
                                goto error;
                        }

                        node = config_node_new ();
                        node->node_type = NODE_TYPE_TOP;
                        pd->pk_config->top_config_node = node;
                }
                break;
        case STATE_IN_CONFIG: /* explicit fallthrough */
        case STATE_IN_MATCH:
                if ((strcmp (el, "match") == 0) && (num_attr == 2)) {

                        node = config_node_new ();
                        node->node_type = NODE_TYPE_MATCH;
                        if (strcmp (attr[0], "action") == 0) {
                                node->data.node_match.match_type = MATCH_TYPE_ACTION;
                        } else if (strcmp (attr[0], "user") == 0) {
                                node->data.node_match.match_type = MATCH_TYPE_USER;
                        } else {
                                _pk_debug ("Unknown match rule '%s'", attr[0]);
                                goto error;
                        }

                        node->data.node_match.data = g_strdup (attr[1]);
                        if (regcomp (&(node->data.node_match.preq), node->data.node_match.data, REG_NOSUB|REG_EXTENDED) != 0) {
                                _pk_debug ("Invalid expression '%s'", node->data.node_match.data);
                                goto error;
                        }

                        state = STATE_IN_MATCH;
                        _pk_debug ("parsed match node ('%s' (%d) -> '%s')", 
                                   attr[0], 
                                   node->data.node_match.match_type,
                                   node->data.node_match.data);

                } else if ((strcmp (el, "return") == 0) && (num_attr == 2)) {

                        node = config_node_new ();
                        node->node_type = NODE_TYPE_RETURN;

                        if (strcmp (attr[0], "result") == 0) {
                                PolKitResult r;
                                if (!polkit_result_from_string_representation (attr[1], &r)) {
                                        _pk_debug ("Unknown return result '%s'", attr[1]);
                                        goto error;
                                }
                                node->data.node_return.result = r;
                        } else {
                                _pk_debug ("Unknown return rule '%s'", attr[0]);
                                goto error;
                        }

                        state = STATE_IN_RETURN;
                        _pk_debug ("parsed return node ('%s' (%d))",
                                   attr[1],
                                   node->data.node_return.result);
                }
                break;
        }

        if (state == STATE_NONE || node == NULL)
                goto error;

        if (pd->stack_depth < 0 || pd->stack_depth >= PARSER_MAX_DEPTH) {
                _pk_debug ("reached max depth?");
                goto error;
        }
        pd->state = state;
        pd->state_stack[pd->stack_depth] = pd->state;
        pd->node_stack[pd->stack_depth] = node;

        if (pd->stack_depth > 0) {
                pd->node_stack[pd->stack_depth - 1]->children = 
                        g_slist_append (pd->node_stack[pd->stack_depth - 1]->children, node);
        }

        pd->stack_depth++;
        _pk_debug ("state = %d", pd->state);
        return;

error:
        if (node != NULL) {
                config_node_unref (node);
        }
        XML_StopParser (pd->parser, FALSE);
}

static void
_cdata (void *data, const char *s, int len)
{
}

static void
_end (void *data, const char *el)
{
        ParserData *pd = data;

        _pk_debug ("_end for node '%s'", el);

        --pd->stack_depth;
        if (pd->stack_depth < 0 || pd->stack_depth >= PARSER_MAX_DEPTH) {
                _pk_debug ("reached max depth?");
                goto error;
        }
        pd->state = pd->state_stack[pd->stack_depth];
        _pk_debug ("state = %d", pd->state);
        return;
error:
        XML_StopParser (pd->parser, FALSE);
}

PolKitConfig *
polkit_config_new (PolKitError **error)
{
        ParserData pd;
        int xml_res;
        PolKitConfig *pk_config;
	char *buf;
	gsize buflen;
        GError *g_error;
        const char *path;

        /* load and parse the configuration file */
        pk_config = NULL;

        path = PACKAGE_SYSCONF_DIR "/PolicyKit/PolicyKit.conf";

        g_error = NULL;
	if (!g_file_get_contents (path, &buf, &buflen, &g_error)) {
                polkit_error_set_error (error, POLKIT_ERROR_POLICY_FILE_INVALID,
                                        "Cannot load PolicyKit policy file at '%s': %s",
                                        path,
                                        g_error->message);
                g_error_free (g_error);
		goto error;
        }

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

        pk_config = g_new0 (PolKitConfig, 1);
        pk_config->refcount = 1;

        pd.state = STATE_NONE;
        pd.pk_config = pk_config;
        pd.node_stack[0] = NULL;
        pd.stack_depth = 0;

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

        _pk_debug ("Loaded configuration file %s", path);

        if (pk_config->top_config_node != NULL)
                config_node_dump (pk_config->top_config_node);

        return pk_config;

error:
        if (pk_config != NULL)
                polkit_config_unref (pk_config);
        return NULL;
}

PolKitConfig *
polkit_config_ref (PolKitConfig *pk_config)
{
        g_return_val_if_fail (pk_config != NULL, pk_config);
        pk_config->refcount++;
        return pk_config;
}

void
polkit_config_unref (PolKitConfig *pk_config)
{
        g_return_if_fail (pk_config != NULL);
        pk_config->refcount--;
        if (pk_config->refcount > 0) 
                return;

        if (pk_config->top_config_node != NULL)
                config_node_unref (pk_config->top_config_node);

        g_free (pk_config);
}

/* exactly one of the parameters caller and session must be NULL */
static PolKitResult
config_node_test (ConfigNode *node, PolKitAction *action, PolKitCaller *caller, PolKitSession *session)
{
        gboolean match;
        gboolean recurse;
        PolKitResult result;
        char *str;
        char *str1;
        char *str2;
        uid_t uid;

        result = POLKIT_RESULT_UNKNOWN_ACTION;
        recurse = FALSE;

        switch (node->node_type) {
        case NODE_TYPE_TOP:
                recurse = TRUE;
                break;
        case NODE_TYPE_MATCH:
                match = FALSE;
                str1 = NULL;
                str2 = NULL;
                switch (node->data.node_match.match_type) {
                case MATCH_TYPE_ACTION:
                        if (!polkit_action_get_action_id (action, &str))
                                goto out;
                        str1 = g_strdup (str);
                        break;
                case MATCH_TYPE_USER:
                        if (caller != NULL) {
                                if (!polkit_caller_get_uid (caller, &uid))
                                        goto out;
                        } else if (session != NULL) {
                                if (!polkit_session_get_uid (session, &uid))
                                        goto out;
                        } else
                                goto out;

                        str1 = g_strdup_printf ("%d", uid);
                        {
                                struct passwd pd;
                                struct passwd* pwdptr=&pd;
                                struct passwd* tempPwdPtr;
                                char pwdbuffer[256];
                                int  pwdlinelen = sizeof(pwdbuffer);

                                if ((getpwuid_r (uid, pwdptr, pwdbuffer, pwdlinelen, &tempPwdPtr)) !=0 )
                                        goto out;
                                str2 = g_strdup (pd.pw_name);
                        }
                        break;
                }

                if (str1 != NULL) {
                        if (regexec (&(node->data.node_match.preq), str1, 0, NULL, 0) == 0)
                                match = TRUE;
                }
                if (!match && str2 != NULL) {
                        if (regexec (&(node->data.node_match.preq), str2, 0, NULL, 0) == 0)
                                match = TRUE;
                }
              

                if (match)
                        recurse = TRUE;

                g_free (str1);
                g_free (str2);
                break;
        case NODE_TYPE_RETURN:
                result = node->data.node_return.result;
                break;
        }

        if (recurse) {
                GSList *i;
                for (i = node->children; i != NULL; i = g_slist_next (i)) {
                        ConfigNode *child_node = i->data;
                        result = config_node_test (child_node, action, caller, session);
                        if (result != POLKIT_RESULT_UNKNOWN_ACTION) {
                                goto out;
                        }
                }
        }

out:
        return result;
}

PolKitResult
polkit_config_can_session_do_action (PolKitConfig   *pk_config,
                                     PolKitAction   *action,
                                     PolKitSession  *session)
{
        PolKitResult result;
        if (pk_config->top_config_node != NULL)
                result = config_node_test (pk_config->top_config_node, action, NULL, session);
        else
                result = POLKIT_RESULT_UNKNOWN_ACTION;
        return result;
}

PolKitResult
polkit_config_can_caller_do_action (PolKitConfig   *pk_config,
                                    PolKitAction   *action,
                                    PolKitCaller   *caller)
{
        PolKitResult result;
        if (pk_config->top_config_node != NULL)
                result = config_node_test (pk_config->top_config_node, action, caller, NULL);
        else
                result = POLKIT_RESULT_UNKNOWN_ACTION;
        return result;
}

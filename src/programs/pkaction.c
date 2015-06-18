/*
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <polkit/polkit.h>

static void
print_action (PolkitActionDescription *action,
              gboolean                 opt_verbose)
{

  if (!opt_verbose)
    {
      g_print ("%s\n", polkit_action_description_get_action_id (action));
    }
  else
    {
      const gchar *vendor;
      const gchar *vendor_url;
      const gchar *icon_name;
      const gchar* const *annotation_keys;
      guint n;

      vendor = polkit_action_description_get_vendor_name (action);
      vendor_url = polkit_action_description_get_vendor_url (action);
      icon_name = polkit_action_description_get_icon_name (action);

      g_print ("%s:\n", polkit_action_description_get_action_id (action));
      g_print ("  description:       %s\n", polkit_action_description_get_description (action));
      g_print ("  message:           %s\n", polkit_action_description_get_message (action));
      if (vendor != NULL)
        g_print ("  vendor:            %s\n", vendor);
      if (vendor_url != NULL)
        g_print ("  vendor_url:        %s\n", vendor_url);

      if (icon_name != NULL)
        g_print ("  icon:              %s\n", icon_name);

      g_print ("  implicit any:      %s\n", polkit_implicit_authorization_to_string (polkit_action_description_get_implicit_any (action)));
      g_print ("  implicit inactive: %s\n", polkit_implicit_authorization_to_string (polkit_action_description_get_implicit_inactive (action)));
      g_print ("  implicit active:   %s\n", polkit_implicit_authorization_to_string (polkit_action_description_get_implicit_active (action)));

      annotation_keys = polkit_action_description_get_annotation_keys (action);
      for (n = 0; annotation_keys[n] != NULL; n++)
        {
          const gchar *key;
          const gchar *value;

          key = annotation_keys[n];
          value = polkit_action_description_get_annotation (action, key);
          g_print ("  annotation:        %s -> %s\n", key, value);
        }
      g_print ("\n");
    }
}

static gint
action_desc_compare_by_action_id_func (PolkitActionDescription *a,
                                       PolkitActionDescription *b)
{
  return g_strcmp0 (polkit_action_description_get_action_id (a),
                    polkit_action_description_get_action_id (b));
}

int
main (int argc, char *argv[])
{
  guint ret;
  gchar *opt_action_id;
  gchar *s;
  gboolean opt_show_version;
  gboolean opt_verbose;
  GOptionEntry options[] =
    {
      {
	"action-id", 'a', 0, G_OPTION_ARG_STRING, &opt_action_id,
	N_("Only output information about ACTION"), N_("ACTION")
      },
      {
	"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose,
	N_("Output detailed action information"), NULL
      },
      {
	"version", 0, 0, G_OPTION_ARG_NONE, &opt_show_version,
	N_("Show version"), NULL
      },
      { NULL, 0, 0, 0, NULL, NULL, NULL }
    };
  GOptionContext *context;
  PolkitAuthority *authority;
  GList *l;
  GList *actions;
  GError *error;

  opt_action_id = NULL;
  context = NULL;
  authority = NULL;
  actions = NULL;
  ret = 1;

  /* Disable remote file access from GIO. */
  setenv ("GIO_USE_VFS", "local", 1);

  opt_show_version = FALSE;
  opt_verbose = FALSE;

  error = NULL;
  context = g_option_context_new (N_("[--action-id ACTION]"));
  s = g_strdup_printf (_("Report bugs to: %s\n"
			 "%s home page: <%s>"), PACKAGE_BUGREPORT,
		       PACKAGE_NAME, PACKAGE_URL);
  g_option_context_set_description (context, s);
  g_free (s);
  g_option_context_add_main_entries (context, options, GETTEXT_PACKAGE);
  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_printerr ("%s: %s\n", g_get_prgname (), error->message);
      g_error_free (error);
      goto out;
    }
  if (argc > 1)
    {
      g_printerr (_("%s: Unexpected argument `%s'\n"), g_get_prgname (),
		  argv[1]);
      goto out;
    }
  if (opt_show_version)
    {
      g_print ("pkaction version %s\n", PACKAGE_VERSION);
      ret = 0;
      goto out;
    }

  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_printerr ("Error getting authority: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  actions = polkit_authority_enumerate_actions_sync (authority,
                                                     NULL,      /* GCancellable */
                                                     &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating actions: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  if (opt_action_id != NULL)
    {
      for (l = actions; l != NULL; l = l->next)
        {
          PolkitActionDescription *action = POLKIT_ACTION_DESCRIPTION (l->data);
          const gchar *id;

          id = polkit_action_description_get_action_id (action);

          if (g_strcmp0 (id, opt_action_id) == 0)
            {
              print_action (action, opt_verbose);
              break;
            }
        }

      if (l == NULL)
        {
          g_printerr ("No action with action id %s\n", opt_action_id);
          goto out;
        }
    }
  else
    {
      actions = g_list_sort (actions,
                             (GCompareFunc) action_desc_compare_by_action_id_func);

      for (l = actions; l != NULL; l = l->next)
        {
          PolkitActionDescription *action = POLKIT_ACTION_DESCRIPTION (l->data);

          print_action (action, opt_verbose);
        }
    }

  ret = 0;

 out:
  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  g_free (opt_action_id);

  if (authority != NULL)
    g_object_unref (authority);

  g_option_context_free (context);

  return ret;
}


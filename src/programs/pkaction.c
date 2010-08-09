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
#include <polkit/polkit.h>

static void
usage (int argc, char *argv[])
{
  GError *error;

  error = NULL;
  if (!g_spawn_command_line_sync ("man pkaction",
                                  NULL,
                                  NULL,
                                  NULL,
                                  &error))
    {
      g_printerr ("Cannot show manual page: %s\n", error->message);
      g_error_free (error);
    }
}

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
  guint n;
  guint ret;
  gchar *action_id;
  gboolean opt_show_help;
  gboolean opt_show_version;
  gboolean opt_verbose;
  PolkitAuthority *authority;
  GList *l;
  GList *actions;
  PolkitActionDescription *description;
  GError *error;

  action_id = NULL;
  authority = NULL;
  actions = NULL;
  description = NULL;
  ret = 1;

  g_type_init ();

  opt_show_help = FALSE;
  opt_show_version = FALSE;
  opt_verbose = FALSE;
  for (n = 1; n < (guint) argc; n++)
    {
      if (g_strcmp0 (argv[n], "--help") == 0)
        {
          opt_show_help = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--version") == 0)
        {
          opt_show_version = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--action-id") == 0 || g_strcmp0 (argv[n], "-a") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
              usage (argc, argv);
              goto out;
            }

          action_id = g_strdup (argv[n]);
        }
      else if (g_strcmp0 (argv[n], "--verbose") == 0 || g_strcmp0 (argv[n], "-v") == 0)
        {
          opt_verbose = TRUE;
        }
    }

  if (opt_show_help)
    {
      usage (argc, argv);
      ret = 0;
      goto out;
    }
  else if (opt_show_version)
    {
      g_print ("pkaction version %s\n", PACKAGE_VERSION);
      ret = 0;
      goto out;
    }

  error = NULL;
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

  if (action_id != NULL)
    {
      for (l = actions; l != NULL; l = l->next)
        {
          PolkitActionDescription *action = POLKIT_ACTION_DESCRIPTION (l->data);
          const gchar *id;

          id = polkit_action_description_get_action_id (action);

          if (g_strcmp0 (id, action_id) == 0)
            {
              print_action (action, opt_verbose);
              break;
            }
        }

      if (l == NULL)
        {
          g_printerr ("No action with action id %s\n", action_id);
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

 out:
  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  if (description != NULL)
    g_object_unref (description);

  g_free (action_id);

  if (authority != NULL)
    g_object_unref (authority);

  return ret;
}


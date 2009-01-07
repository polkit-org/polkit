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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>
#include <polkit/polkit.h>

static PolkitAuthority *authority;

static gboolean opt_list_actions = FALSE;
static gboolean opt_list_users   = FALSE;
static gboolean opt_list_groups  = FALSE;
static gchar *opt_show_action    = NULL;
static gboolean opt_show_version = FALSE;

static GOptionEntry option_entries[] = {
  {"list-actions", 'l', 0, G_OPTION_ARG_NONE, &opt_list_actions, "List registered actions", NULL},
  {"list-users", 0, 0, G_OPTION_ARG_NONE, &opt_list_users, "List known users", NULL},
  {"list-groups", 0, 0, G_OPTION_ARG_NONE, &opt_list_groups, "List known groups", NULL},
  {"show-action", 's', 0, G_OPTION_ARG_STRING, &opt_show_action, "Show details for an action", "action_id"},
  {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_show_version, "Show version", NULL},
  {NULL, },
};

static gboolean list_actions (void);
static gboolean list_users (void);
static gboolean list_groups (void);

static gboolean show_action (const gchar *action_id);

int
main (int argc, char *argv[])
{
  gboolean ret;
  GError *error;
  GOptionContext *option_ctx;

  ret = FALSE;

  g_type_init ();

  option_ctx = g_option_context_new ("polkit-1");
  g_option_context_add_main_entries (option_ctx, option_entries, NULL);
  g_option_context_set_summary (option_ctx, "PolicyKit commandline tool");
  error = NULL;
  if (!g_option_context_parse (option_ctx, &argc, &argv, &error))
    {
      g_printerr ("Error parsing options: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  authority = polkit_authority_get ();

  if (opt_list_actions)
    {
      ret = list_actions ();
    }
  else if (opt_list_users)
    {
      ret = list_users ();
    }
  else if (opt_list_groups)
    {
      ret = list_groups ();
    }
  else if (opt_show_action != NULL)
    {
      ret = show_action (opt_show_action);
    }
  else if (opt_show_version)
    {
      g_print ("polkit-1 %s\n", PACKAGE_VERSION);
      ret = TRUE;
    }
  else
    {
      gchar *s;

      /* print usage */
      s = g_option_context_get_help (option_ctx, TRUE, NULL);
      g_print ("%s", s);
      g_free (s);
      ret = 0;
      goto out;
    }

  g_object_unref (authority);

  g_option_context_free (option_ctx);

 out:
  g_free (opt_show_action);

  return ret ? 0 : 1;
}

static void
print_action (PolkitActionDescription *action)
{
  const gchar *vendor;
  const gchar *vendor_url;
  GIcon *icon;
  const gchar * const *annotation_keys;
  guint n;

  vendor = polkit_action_description_get_vendor_name (action);
  vendor_url = polkit_action_description_get_vendor_url (action);
  icon = polkit_action_description_get_icon (action);

  g_print ("action_id:       %s\n", polkit_action_description_get_action_id (action));
  g_print ("description:     %s\n", polkit_action_description_get_description (action));
  g_print ("message:         %s\n", polkit_action_description_get_message (action));
  if (vendor != NULL)
    g_print ("vendor:          %s\n", vendor);
  if (vendor_url != NULL)
    g_print ("vendor_url:      %s\n", vendor_url);

  if (icon != NULL)
    {
      gchar *s;
      s = g_icon_to_string (icon);
      g_print ("icon:            %s\n", s);
      g_free (s);
    }

  annotation_keys = polkit_action_description_get_annotation_keys (action);
  for (n = 0; annotation_keys[n] != NULL; n++)
    {
      const gchar *key;
      const gchar *value;

      key = annotation_keys[n];
      value = polkit_action_description_get_annotation (action, key);
      g_print ("annotation:      %s -> %s\n", key, value);
    }
}

static gboolean
show_action (const gchar *action_id)
{
  gboolean ret;
  GError *error;
  GList *actions;
  GList *l;

  ret = FALSE;

  error = NULL;
  actions = polkit_authority_enumerate_actions_sync (authority,
                                                     NULL,
                                                     NULL,
                                                     &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating actions: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  for (l = actions; l != NULL; l = l->next)
    {
      PolkitActionDescription *action = POLKIT_ACTION_DESCRIPTION (l->data);
      const gchar *id;

      id = polkit_action_description_get_action_id (action);

      if (strcmp (id, action_id) == 0)
        {
          print_action (action);
          break;
        }
    }

  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  if (l != NULL)
    {
      ret = TRUE;
    }
  else
    {
      g_printerr ("Error: No action with action id %s\n", action_id);
    }

 out:
  return ret;
}

static gboolean
list_actions (void)
{
  gboolean ret;
  GError *error;
  GList *actions;
  GList *l;

  ret = FALSE;

  error = NULL;
  actions = polkit_authority_enumerate_actions_sync (authority,
                                                     NULL,
                                                     NULL,
                                                     &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating actions: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  for (l = actions; l != NULL; l = l->next)
    {
      PolkitActionDescription *action = POLKIT_ACTION_DESCRIPTION (l->data);

      g_print ("%s\n", polkit_action_description_get_action_id (action));
    }

  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  ret = TRUE;

 out:
  return ret;
}

static void
print_subjects (GList *subjects)
{
  GList *l;

  for (l = subjects; l != NULL; l = l->next)
    {
      PolkitSubject *subject = POLKIT_SUBJECT (l->data);
      gchar *s;

      s = polkit_subject_to_string (subject);
      g_print ("%s\n", s);
      g_free (s);
    }
}

static gboolean
list_users (void)
{
  gboolean ret;
  GError *error;
  GList *subjects;

  ret = FALSE;

  error = NULL;
  subjects = polkit_authority_enumerate_users_sync (authority,
                                                    NULL,
                                                    &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating users: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  print_subjects (subjects);

  g_list_foreach (subjects, (GFunc) g_object_unref, NULL);
  g_list_free (subjects);

  ret = TRUE;

 out:
  return ret;
}

static gboolean
list_groups (void)
{
  gboolean ret;
  GError *error;
  GList *subjects;

  ret = FALSE;

  error = NULL;
  subjects = polkit_authority_enumerate_groups_sync (authority,
                                                     NULL,
                                                     &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating users: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  print_subjects (subjects);

  g_list_foreach (subjects, (GFunc) g_object_unref, NULL);
  g_list_free (subjects);

  ret = TRUE;

 out:
  return ret;
}


#if 0
        PolkitSubject *subject1;
        PolkitSubject *subject2;
        PolkitSubject *subject3;

        subject1 = polkit_user_new ("moe");
        subject2 = polkit_user_new ("bernie");
        subject3 = polkit_process_new (42);

        GList *claims;
        claims = NULL;
        claims = g_list_prepend (claims, polkit_authorization_claim_new (subject1, "org.foo.1"));
        claims = g_list_prepend (claims, polkit_authorization_claim_new (subject2, "org.foo.2"));
        claims = g_list_prepend (claims, polkit_authorization_claim_new (subject3, "org.foo.3"));

        PolkitAuthorizationClaim *claim;
        claim = polkit_authorization_claim_new (subject3, "org.foo.4");
        polkit_authorization_claim_set_attribute (claim, "foo", "bar");
        polkit_authorization_claim_set_attribute (claim, "unix-device", "/dev/sda");
        claims = g_list_prepend (claims, claim);


        error = NULL;
        result = polkit_authority_check_claims_sync (authority,
                                                       claims,
                                                       NULL,
                                                       &error);
        if (error != NULL) {
                g_print ("Got error: %s\n", error->message);
                g_error_free (error);
        } else {
                g_print ("Got result: %d\n", result);
        }

#endif

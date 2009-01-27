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

static gboolean opt_list_actions  = FALSE;
static gboolean opt_list_users    = FALSE;
static gboolean opt_list_groups   = FALSE;
static gboolean opt_list_authorizations  = FALSE;
static gboolean opt_list_explicit_authorizations  = FALSE;
static gboolean opt_check = FALSE;
static gboolean opt_grant = FALSE;
static gboolean opt_revoke = FALSE;
static gboolean opt_run = FALSE;

static gboolean opt_show_help = FALSE;
static gboolean opt_show_version = FALSE;

static gboolean opt_verbose = FALSE;

static PolkitSubject *subject = NULL;
static PolkitIdentity *identity = NULL;

static gchar *action_id = NULL;

/* ---------------------------------------------------------------------------------------------------- */

static gboolean list_actions (void);
static gboolean list_users (void);
static gboolean list_groups (void);
static gboolean list_authorizations (void);
static gboolean list_explicit_authorizations (void);

static gboolean do_run (gint argc, gchar *argv[]);
static gboolean do_check (void);
static gboolean do_grant (void);
static gboolean do_revoke (void);

static gboolean show_action (const gchar *action_id);

/* ---------------------------------------------------------------------------------------------------- */

static void
usage (int argc, char *argv[])
{
  GError *error;

  error = NULL;
  if (!g_spawn_command_line_sync ("man polkit-1",
                                  NULL,
                                  NULL,
                                  NULL,
                                  &error))
    {
      g_printerr ("Cannot show manual page: %s\n", error->message);
      g_error_free (error);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

int
main (int argc, char *argv[])
{
  gint n;
  gboolean ret;
  gboolean in_list;
  gboolean stop_processing_args;
  GError *error;

  ret = FALSE;
  error = NULL;

  g_type_init ();

  in_list = FALSE;
  stop_processing_args = FALSE;
  for (n = 1; n < argc && !stop_processing_args; n++)
    {
      if (in_list)
        {
          if (strcmp (argv[n], "actions") == 0)
            {
              opt_list_actions = TRUE;
            }
          else if (strcmp (argv[n], "users") == 0)
            {
              opt_list_users = TRUE;
            }
          else if (strcmp (argv[n], "groups") == 0)
            {
              opt_list_groups = TRUE;
            }
          else if (strcmp (argv[n], "authorizations") == 0)
            {
              opt_list_authorizations = TRUE;
            }
          else if (strcmp (argv[n], "explicit-authorizations") == 0)
            {
              opt_list_explicit_authorizations = TRUE;

              n++;
              if (n >= argc)
                {
                  usage (argc, argv);
                  goto out;
                }

              identity = polkit_identity_from_string (argv[n], &error);
              if (identity == NULL)
                {
                  g_printerr ("Error parsing identity: %s\n", error->message);
                  g_error_free (error);
                  goto out;
                }

            }
          else
            {
              usage (argc, argv);
              goto out;
            }

          in_list = FALSE;
        }
      else if (strcmp (argv[n], "list") == 0)
        {
          in_list = TRUE;
          continue;
        }
      else if (strcmp (argv[n], "run") == 0)
        {
          opt_run = TRUE;

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          action_id = g_strdup (argv[n]);

          if (n + 1 >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          stop_processing_args = TRUE;
        }
      else if (strcmp (argv[n], "check") == 0)
        {
          opt_check = TRUE;

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          subject = polkit_subject_from_string (argv[n], &error);
          if (subject == NULL)
            {
              g_printerr ("Error parsing subject: %s\n", error->message);
              g_error_free (error);
              goto out;
            }

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          action_id = g_strdup (argv[n]);
        }
      else if (strcmp (argv[n], "grant") == 0)
        {
          opt_grant = TRUE;

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          identity = polkit_identity_from_string (argv[n], &error);
          if (identity == NULL)
            {
              g_printerr ("Error parsing identity: %s\n", error->message);
              g_error_free (error);
              goto out;
            }

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          action_id = g_strdup (argv[n]);
        }
      else if (strcmp (argv[n], "revoke") == 0)
        {
          opt_revoke = TRUE;

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          identity = polkit_identity_from_string (argv[n], &error);
          if (identity == NULL)
            {
              g_printerr ("Error parsing identity: %s\n", error->message);
              g_error_free (error);
              goto out;
            }

          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          action_id = g_strdup (argv[n]);
        }
      else if (strcmp (argv[n], "--subject") == 0)
        {
          n++;
          if (n >= argc)
            {
              usage (argc, argv);
              goto out;
            }

          subject = polkit_subject_from_string (argv[n], &error);
          if (subject == NULL)
            {
              g_printerr ("Error parsing subject: %s\n", error->message);
              g_error_free (error);
              goto out;
            }
        }
      else if (strcmp (argv[n], "--help") == 0)
        {
          opt_show_help = TRUE;
        }
      else if (strcmp (argv[n], "--version") == 0)
        {
          opt_show_version = TRUE;
        }
      else if (strcmp (argv[n], "--verbose") == 0)
        {
          opt_verbose = TRUE;
        }
      else
        {
          usage (argc, argv);
          goto out;
        }
    }

  authority = polkit_authority_get ();

  if (opt_show_help)
    {
      usage (argc, argv);
      ret = TRUE;
      goto out;
    }
  else if (opt_show_version)
    {
      g_print ("PolicyKit version %s\n", PACKAGE_VERSION);
      /* TODO: print backend name / version */
      ret = TRUE;
      goto out;
    }
  else if (opt_list_actions)
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
  else if (opt_list_authorizations)
    {
      ret = list_authorizations ();
    }
  else if (opt_list_explicit_authorizations)
    {
      ret = list_explicit_authorizations ();
    }
  else if (opt_run)
    {
      if (action_id == NULL)
        {
          usage (argc, argv);
          goto out;
        }

      ret = do_run (argc - n, argv + n);
    }
  else if (opt_check)
    {
      if (subject == NULL || action_id == NULL)
        {
          usage (argc, argv);
          goto out;
        }

      ret = do_check ();
    }
  else if (opt_grant)
    {
      if (identity == NULL || action_id == NULL)
        {
          usage (argc, argv);
          goto out;
        }

      ret = do_grant ();
    }
  else if (opt_revoke)
    {
      if (identity == NULL || action_id == NULL)
        {
          usage (argc, argv);
          goto out;
        }

      ret = do_revoke ();
    }
  else
    {
      usage (argc, argv);
    }


 out:
  if (authority != NULL)
    g_object_unref (authority);

  if (subject != NULL)
    g_object_unref (subject);

  if (identity != NULL)
    g_object_unref (identity);

  g_free (action_id);

  return ret ? 0 : 1;
}

/* ---------------------------------------------------------------------------------------------------- */

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

  g_print ("%s:\n", polkit_action_description_get_action_id (action));
  g_print ("  description:       %s\n", polkit_action_description_get_description (action));
  g_print ("  message:           %s\n", polkit_action_description_get_message (action));
  if (vendor != NULL)
    g_print ("  vendor:            %s\n", vendor);
  if (vendor_url != NULL)
    g_print ("  vendor_url:        %s\n", vendor_url);

  if (icon != NULL)
    {
      gchar *s;
      s = g_icon_to_string (icon);
      g_print ("  icon:              %s\n", s);
      g_free (s);
    }

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
}

/* ---------------------------------------------------------------------------------------------------- */

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
      const gchar *action_id;

      action_id = polkit_action_description_get_action_id (action);

      if (opt_verbose)
        {
          show_action (action_id);
          g_print ("\n");
        }
      else
        {
          g_print ("%s\n", action_id);
        }
    }

  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static void
print_identities (GList *identities)
{
  GList *l;

  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      gchar *s;

      s = polkit_identity_to_string (identity);
      g_print ("%s\n", s);
      g_free (s);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
list_users (void)
{
  gboolean ret;
  GError *error;
  GList *identities;

  ret = FALSE;

  error = NULL;
  identities = polkit_authority_enumerate_users_sync (authority,
                                                    NULL,
                                                    &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating users: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  print_identities (identities);

  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
list_groups (void)
{
  gboolean ret;
  GError *error;
  GList *identities;

  ret = FALSE;

  error = NULL;
  identities = polkit_authority_enumerate_groups_sync (authority,
                                                     NULL,
                                                     &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating users: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  print_identities (identities);

  g_list_foreach (identities, (GFunc) g_object_unref, NULL);
  g_list_free (identities);

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gint
do_run (gint argc, gchar *argv[])
{
  PolkitAuthorizationResult result;
  PolkitSubject *calling_process;
  GError *error;
  gboolean ret;

  ret = FALSE;
  error = NULL;

  calling_process = polkit_unix_process_new (getpid ());

  result = polkit_authority_check_authorization_sync (authority,
                                                      calling_process,
                                                      action_id,
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION,
                                                      NULL,
                                                      &error);
  if (error != NULL)
    {
      g_printerr ("Error checking authorization for action %s: %s\n", action_id, error->message);
      g_error_free (error);
      goto out;
    }

  if (result != POLKIT_AUTHORIZATION_RESULT_AUTHORIZED)
    {
      g_printerr ("Error obtaining authorization for action %s\n", action_id);
      goto out;
    }

  execvp (argv[0], argv);

  g_printerr ("Error launching program: %m\n");

 out:

  g_object_unref (calling_process);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
do_check (void)
{
  PolkitAuthorizationResult result;
  GError *error;

  error = NULL;
  result = POLKIT_AUTHORIZATION_RESULT_NOT_AUTHORIZED;

  result = polkit_authority_check_authorization_sync (authority,
                                                      subject,
                                                      action_id,
                                                      POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                                      NULL,
                                                      &error);
  if (error != NULL)
    {
      g_printerr ("Error checking authorization: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

 out:

  return result == POLKIT_AUTHORIZATION_RESULT_AUTHORIZED;
}

/* ---------------------------------------------------------------------------------------------------- */


typedef struct
{
  gchar *action_id;
  PolkitAuthorizationResult result;
} AuthzData;

static GPtrArray *authz_data_array;

static gint authz_data_num_pending = 0;

static GMainLoop *authz_data_loop = NULL;

static void
authz_data_free (AuthzData *data)
{
  g_free (data->action_id);
  g_free (data);
}

static gint
authz_data_sort_func (gconstpointer a,
                      gconstpointer b)
{
  AuthzData *data_a;
  AuthzData *data_b;

  data_a = (AuthzData *) *((gpointer **) a);
  data_b = (AuthzData *) *((gpointer **) b);

  return strcmp (data_a->action_id, data_b->action_id);
}

static void
list_authz_cb (GObject      *source_obj,
               GAsyncResult *res,
               gpointer      user_data)
{
  PolkitAuthority *authority;
  AuthzData *data;
  GError *error;
  PolkitAuthorizationResult result;

  authority = POLKIT_AUTHORITY (source_obj);
  data = user_data;
  error = NULL;

  result = polkit_authority_check_authorization_finish (authority,
                                                        res,
                                                        &error);
  if (error != NULL)
    {
      g_printerr ("Unable to check authorization: %s\n", error->message);
      g_error_free (error);
    }
  else
    {
      data->result = result;
    }

  authz_data_num_pending -= 1;

  if (authz_data_num_pending == 0)
    g_main_loop_quit (authz_data_loop);
}

static gboolean
list_authorizations (void)
{
  GError *error;
  GList *actions;
  GList *l;
  gboolean ret;
  PolkitSubject *calling_process;
  guint n;

  ret = FALSE;

  authz_data_array = g_ptr_array_new ();
  authz_data_num_pending = 0;
  authz_data_loop = g_main_loop_new (NULL, FALSE);

  calling_process = polkit_unix_process_new (getppid ());

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
      const gchar *action_id;
      AuthzData *data;

      action_id = polkit_action_description_get_action_id (action);

      data = g_new0 (AuthzData, 1);
      data->action_id = g_strdup (action_id);

      g_ptr_array_add (authz_data_array, data);

      authz_data_num_pending += 1;

      polkit_authority_check_authorization (authority,
                                            calling_process,
                                            action_id,
                                            POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE,
                                            NULL,
                                            list_authz_cb,
                                            data);
    }

  g_main_loop_run (authz_data_loop);

  ret = TRUE;

  /* sort authorizations by name */
  g_ptr_array_sort (authz_data_array, authz_data_sort_func);

  for (n = 0; n < authz_data_array->len; n++)
    {
      AuthzData *data = authz_data_array->pdata[n];

      if (data->result == POLKIT_AUTHORIZATION_RESULT_AUTHORIZED)
        g_print ("%s\n", data->action_id);
    }

 out:

  g_list_foreach (actions, (GFunc) g_object_unref, NULL);
  g_list_free (actions);

  g_ptr_array_foreach (authz_data_array, (GFunc) authz_data_free, NULL);
  g_ptr_array_free (authz_data_array, TRUE);

  g_object_unref (calling_process);

  g_main_loop_unref (authz_data_loop);
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
list_explicit_authorizations (void)
{
  gboolean ret;
  GError *error;
  GList *authorizations;
  GList *l;

  ret = FALSE;

  error = NULL;
  authorizations = polkit_authority_enumerate_authorizations_sync (authority,
                                                                   identity,
                                                                   NULL,
                                                                   &error);
  if (error != NULL)
    {
      g_printerr ("Error enumerating authorizations: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  for (l = authorizations; l != NULL; l = l->next)
    {
      PolkitAuthorization *authorization = POLKIT_AUTHORIZATION (l->data);
      const gchar *action_id;

      action_id = polkit_authorization_get_action_id (authorization);

      if (opt_verbose)
        {
          gchar *constrain_str;
          PolkitSubject *subject;

          subject = polkit_authorization_get_subject (authorization);
          if (subject != NULL)
            constrain_str = polkit_subject_to_string (subject);
          else
            constrain_str = g_strdup ("<nothing>");

          g_print ("%s:\n", action_id);
          g_print ("  constrained to: %s\n", constrain_str);
          g_print ("\n");

          g_free (constrain_str);
        }
      else
        {
          g_print ("%s\n", action_id);
        }
    }

  g_list_foreach (authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (authorizations);

  ret = TRUE;

 out:
  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
do_grant (void)
{
  PolkitAuthorization *authorization;
  gboolean ret;
  GError *error;

  error = NULL;
  ret = FALSE;

  authorization = polkit_authorization_new (action_id,
                                            subject,
                                            FALSE); /* TODO: handle negative */

  if (!polkit_authority_add_authorization_sync (authority,
                                                identity,
                                                authorization,
                                                NULL,
                                                &error))
    {
      g_printerr ("Error adding authorization: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  ret = TRUE;

 out:

  g_object_unref (authorization);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

static gboolean
do_revoke (void)
{
  PolkitAuthorization *authorization;
  gboolean ret;
  GError *error;

  error = NULL;
  ret = FALSE;

  authorization = polkit_authorization_new (action_id,
                                            subject,
                                            FALSE); /* TODO: handle negative */

  if (!polkit_authority_remove_authorization_sync (authority,
                                                   identity,
                                                   authorization,
                                                   NULL,
                                                   &error))
    {
      g_printerr ("Error removing authorization: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  ret = TRUE;

 out:

  g_object_unref (authorization);

  return ret;
}

/* ---------------------------------------------------------------------------------------------------- */

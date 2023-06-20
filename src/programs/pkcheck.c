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
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>

static void
help (void)
{
  g_print (_("Usage:\n"
"  pkcheck [OPTION...]\n"
"\n"
"Help Options:\n"
"  -h, --help                         Show help options\n"
"\n"
"Application Options:\n"
"  -a, --action-id=ACTION             Check authorization to perform ACTION\n"
"  -u, --allow-user-interaction       Interact with the user if necessary\n"
"  -d, --details=KEY VALUE            Add (KEY, VALUE) to information about the action\n"
"  --enable-internal-agent            Use an internal authentication agent if necessary\n"
"  --list-temp                        List temporary authorizations for current session\n"
"  -p, --process=PID[,START_TIME,UID] Check authorization of specified process\n"
"  --revoke-temp                      Revoke all temporary authorizations for current session\n"
"  -s, --system-bus-name=BUS_NAME     Check authorization of owner of BUS_NAME\n"
"  --version                          Show version\n"
	     "\n"
	     "Report bugs to: %s\n"
	     "%s home page: <%s>\n"), PACKAGE_BUGREPORT, PACKAGE_NAME,
	   PACKAGE_URL);
}

static gchar *
escape_str (const gchar *str)
{
  GString *s;
  guint n;

  s = g_string_new (NULL);
  if (str == NULL)
    goto out;

  for (n = 0; str[n] != '\0'; n++)
    {
      guint c = str[n] & 0xff;

      if (g_ascii_isalnum (c) || c=='_')
        g_string_append_c (s, c);
      else
        g_string_append_printf (s, "\\%o", c);
    }

 out:
  return g_string_free (s, FALSE);
}

static gchar *
format_reltime (gint seconds)
{
  gint magnitude;
  const gchar *ending;
  gchar *ret;

  if (seconds >= 0)
    {
      magnitude = seconds;
      ending = "from now";
    }
  else
    {
      magnitude = -seconds;
      ending = "ago";
    }

  if (magnitude >= 60)
    {
      ret = g_strdup_printf ("%d min %d sec %s", magnitude/60, magnitude%60, ending);
    }
  else
    {
      ret = g_strdup_printf ("%d sec %s", magnitude, ending);
    }

  return ret;
}

/* TODO: should probably move to PolkitSubject
 * (also see copy in src/polkitbackend/polkitbackendinteractiveauthority.c)
 *
 * Also, can't really trust the cmdline... but might be useful in the logs anyway.
 */
static gchar *
_polkit_subject_get_cmdline (PolkitSubject *subject)
{
  PolkitSubject *process;
  gchar *ret;
  gint pid;
  gchar *filename;
  gchar *contents;
  gsize contents_len;
  GError *error;
  guint n;

  g_return_val_if_fail (subject != NULL, NULL);

  error = NULL;

  ret = NULL;
  process = NULL;
  filename = NULL;
  contents = NULL;

  if (POLKIT_IS_UNIX_PROCESS (subject))
    {
      process = g_object_ref (subject);
    }
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      process = polkit_system_bus_name_get_process_sync (POLKIT_SYSTEM_BUS_NAME (subject),
                                                         NULL,
                                                         &error);
      if (process == NULL)
        {
          g_printerr ("Error getting process for system bus name `%s': %s\n",
                      polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (subject)),
                      error->message);
          g_error_free (error);
          goto out;
        }
    }
  else
    {
      g_warning ("Unknown subject type passed to _polkit_subject_get_cmdline()");
      goto out;
    }

  pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (process));

  filename = g_strdup_printf ("/proc/%d/cmdline", pid);

  if (!g_file_get_contents (filename,
                            &contents,
                            &contents_len,
                            &error))
    {
      g_printerr ("Error opening `%s': %s\n",
                  filename,
                  error->message);
      g_error_free (error);
      goto out;
    }

  if (contents == NULL || contents_len == 0)
    {
      goto out;
    }
  else
    {
      /* The kernel uses '\0' to separate arguments - replace those with a space. */
      for (n = 0; n < contents_len - 1; n++)
        {
          if (contents[n] == '\0')
            contents[n] = ' ';
        }
      ret = g_strdup (contents);
      g_strstrip (ret);
    }

 out:
  g_free (filename);
  g_free (contents);
  if (process != NULL)
    g_object_unref (process);
  return ret;
}

static gint
do_list_or_revoke_temp_authz (gboolean revoke)
{
  gint ret;
  PolkitAuthority *authority;
  PolkitSubject *session;
  GError *error;

  ret = 1;
  authority = NULL;
  session = NULL;

  error = NULL;
  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_printerr ("Error getting authority: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  session = polkit_unix_session_new_for_process_sync (getpid (),
                                                      NULL, /* GCancellable */
                                                      &error);
  if (session == NULL)
    {
      g_printerr ("Error getting session: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  if (revoke)
    {
      if (!polkit_authority_revoke_temporary_authorizations_sync (authority,
                                                                  session,
                                                                  NULL, /* GCancellable */
                                                                  &error))
        {
          g_printerr ("Error revoking temporary authorizations: %s\n", error->message);
          g_error_free (error);
          goto out;
        }

      ret = 0;
    }
  else
    {
      GList *authorizations;
      GList *l;

      error = NULL;
      authorizations = polkit_authority_enumerate_temporary_authorizations_sync (authority,
                                                                                 session,
                                                                                 NULL, /* GCancellable */
                                                                                 &error);
      if (error != NULL)
        {
          g_printerr ("Error getting temporary authorizations: %s\n", error->message);
          g_error_free (error);
          goto out;
        }

      for (l = authorizations; l != NULL; l = l->next)
        {
          PolkitTemporaryAuthorization *a = POLKIT_TEMPORARY_AUTHORIZATION (l->data);
          const gchar *id;
          const gchar *action_id;
          PolkitSubject *subject;
          gchar *subject_cmdline;
          time_t obtained;
          time_t expires;
          GTimeVal now;
          gchar *subject_str;
          gchar obtained_str[64];
          gchar expires_str[64];
          gchar *obtained_rel_str;
          gchar *expires_rel_str;
          struct tm *broken_down;

          id = polkit_temporary_authorization_get_id (a);
          action_id = polkit_temporary_authorization_get_action_id (a);
          subject = polkit_temporary_authorization_get_subject (a);
          subject_str = polkit_subject_to_string (subject);
          subject_cmdline = _polkit_subject_get_cmdline (subject);
          obtained = polkit_temporary_authorization_get_time_obtained (a);
          expires = polkit_temporary_authorization_get_time_expires (a);

          g_get_current_time (&now);

          broken_down = localtime (&obtained);
          strftime (obtained_str, sizeof (obtained_str), "%c", broken_down);
          broken_down = localtime (&expires);
          strftime (expires_str, sizeof (expires_str), "%c", broken_down);

          obtained_rel_str = format_reltime (obtained - now.tv_sec);
          expires_rel_str = format_reltime (expires - now.tv_sec);

          g_print ("authorization id: %s\n"
                   "action:           %s\n"
                   "subject:          %s (%s)\n"
                   "obtained:         %s (%s)\n"
                   "expires:          %s (%s)\n"
                   "\n",
                   id,
                   action_id,
                   subject_str, subject_cmdline != NULL ? subject_cmdline : "cannot read cmdline",
                   obtained_rel_str, obtained_str,
                   expires_rel_str, expires_str);

          g_object_unref (subject);
          g_free (subject_str);
          g_free (subject_cmdline);
          g_free (obtained_rel_str);
          g_free (expires_rel_str);
        }
      g_list_foreach (authorizations, (GFunc) g_object_unref, NULL);
      g_list_free (authorizations);

      ret = 0;
    }

 out:
  if (authority != NULL)
    g_object_unref (authority);
  if (session != NULL)
    g_object_unref (session);

  return ret;
}

int
main (int argc, char *argv[])
{
  guint n;
  guint ret;
  gchar *action_id;
  gboolean opt_show_help;
  gboolean opt_show_version;
  gboolean allow_user_interaction;
  gboolean enable_internal_agent;
  gboolean list_temp;
  gboolean revoke_temp;
  PolkitAuthority *authority;
  PolkitAuthorizationResult *result;
  PolkitSubject *subject;
  PolkitDetails *details;
  PolkitCheckAuthorizationFlags flags;
  PolkitDetails *result_details;
  GError *error;
  gpointer local_agent_handle;

  subject = NULL;
  action_id = NULL;
  details = NULL;
  authority = NULL;
  result = NULL;
  allow_user_interaction = FALSE;
  enable_internal_agent = FALSE;
  list_temp = FALSE;
  revoke_temp = FALSE;
  local_agent_handle = NULL;
  ret = 126;

  if (argc < 1)
    {
      exit(126);
    }

  /* Disable remote file access from GIO. */
  setenv ("GIO_USE_VFS", "local", 1);

  details = polkit_details_new ();

  opt_show_help = FALSE;
  opt_show_version = FALSE;
  g_set_prgname ("pkcheck");
  for (n = 1; n < (guint) argc; n++)
    {
      if (g_strcmp0 (argv[n], "--help") == 0 || g_strcmp0 (argv[n], "-h") == 0)
        {
          opt_show_help = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--version") == 0)
        {
          opt_show_version = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--process") == 0 || g_strcmp0 (argv[n], "-p") == 0)
        {
          gint pid;
	  guint uid;
          guint64 pid_start_time;

          n++;
          if (n >= (guint) argc)
            {
	      g_printerr (_("%s: Argument expected after `%s'\n"),
			  g_get_prgname (), "--process, -p");
              goto out;
            }

          if (sscanf (argv[n], "%i,%" G_GUINT64_FORMAT ",%u", &pid, &pid_start_time, &uid) == 3)
            {
              subject = polkit_unix_process_new_for_owner (pid, pid_start_time, uid);
            }
          else if (sscanf (argv[n], "%i,%" G_GUINT64_FORMAT, &pid, &pid_start_time) == 2)
            {
	      G_GNUC_BEGIN_IGNORE_DEPRECATIONS
              subject = polkit_unix_process_new_full (pid, pid_start_time);
	      G_GNUC_END_IGNORE_DEPRECATIONS
            }
          else if (sscanf (argv[n], "%i", &pid) == 1)
            {
	      G_GNUC_BEGIN_IGNORE_DEPRECATIONS
              subject = polkit_unix_process_new (pid);
	      G_GNUC_END_IGNORE_DEPRECATIONS
            }
          else
            {
	      g_printerr (_("%s: Invalid --process value `%s'\n"),
			  g_get_prgname (), argv[n]);
              goto out;
            }
        }
      else if (g_strcmp0 (argv[n], "--system-bus-name") == 0 || g_strcmp0 (argv[n], "-s") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
	      g_printerr (_("%s: Argument expected after `%s'\n"),
			  g_get_prgname (), "--system-bus-name, -s");
              goto out;
            }

          subject = polkit_system_bus_name_new (argv[n]);
        }
      else if (g_strcmp0 (argv[n], "--action-id") == 0 || g_strcmp0 (argv[n], "-a") == 0)
        {
          n++;
          if (n >= (guint) argc)
            {
	      g_printerr (_("%s: Argument expected after `%s'\n"),
			  g_get_prgname (), "--action-id, -a");
              goto out;
            }

          action_id = g_strdup (argv[n]);
        }
      else if (g_strcmp0 (argv[n], "--detail") == 0 || g_strcmp0 (argv[n], "-d") == 0)
        {
          const gchar *key;
          const gchar *value;

          n++;
          if (n >= (guint) argc)
            {
	      g_printerr (_("%s: Two arguments expected after `--detail, -d'\n"),
			  g_get_prgname ());
              goto out;
            }
          key = argv[n];

          n++;
          if (n >= (guint) argc)
            {
	      g_printerr (_("%s: Two arguments expected after `--detail, -d'\n"),
			  g_get_prgname ());
              goto out;
            }
          value = argv[n];

          polkit_details_insert (details, key, value);
        }
      else if (g_strcmp0 (argv[n], "--allow-user-interaction") == 0 || g_strcmp0 (argv[n], "-u") == 0)
        {
          allow_user_interaction = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--enable-internal-agent") == 0)
        {
          enable_internal_agent = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--list-temp") == 0)
        {
          list_temp = TRUE;
        }
      else if (g_strcmp0 (argv[n], "--revoke-temp") == 0)
        {
          revoke_temp = TRUE;
        }
      else
        {
          break;
        }
    }
  if (argv[n] != NULL)
    {
      g_printerr (_("%s: Unexpected argument `%s'\n"), g_get_prgname (),
		  argv[n]);
      goto out;
    }

  if (opt_show_help)
    {
      help ();
      ret = 0;
      goto out;
    }
  else if (opt_show_version)
    {
      g_print ("pkcheck version %s\n", PACKAGE_VERSION);
      ret = 0;
      goto out;
    }

  if (list_temp)
    {
      ret = do_list_or_revoke_temp_authz (FALSE);
      goto out;
    }
  else if (revoke_temp)
    {
      ret = do_list_or_revoke_temp_authz (TRUE);
      goto out;
    }
  else if (subject == NULL)
    {
      g_printerr (_("%s: Subject not specified\n"), g_get_prgname ());
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

 try_again:
  error = NULL;
  flags = POLKIT_CHECK_AUTHORIZATION_FLAGS_NONE;
  if (allow_user_interaction)
    flags |= POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION;
  result = polkit_authority_check_authorization_sync (authority,
                                                      subject,
                                                      action_id,
                                                      details,
                                                      flags,
                                                      NULL,
                                                      &error);
  if (result == NULL)
    {
      g_printerr ("Error checking for authorization %s: %s\n",
                  action_id,
                  error ? error->message : "Could not verify; error object not present.");
      ret = 127;
      goto out;
    }

  result_details = polkit_authorization_result_get_details (result);
  if (result_details != NULL)
    {
      gchar **keys;

      keys = polkit_details_get_keys (result_details);
      for (n = 0; keys != NULL && keys[n] != NULL; n++)
        {
          const gchar *key;
          const gchar *value;
          gchar *s;

          key = keys[n];
          value = polkit_details_lookup (result_details, key);

          s = escape_str (key);
          g_print ("%s", s);
          g_free (s);
          g_print ("=");
          s = escape_str (value);
          g_print ("%s", s);
          g_free (s);
          g_print ("\n");
        }

      g_strfreev (keys);
    }

  if (polkit_authorization_result_get_is_authorized (result))
    {
      ret = 0;
    }
  else if (polkit_authorization_result_get_is_challenge (result))
    {
      if (allow_user_interaction)
        {
          if (local_agent_handle == NULL && enable_internal_agent)
            {
              PolkitAgentListener *listener;
              error = NULL;
              /* this will fail if we can't find a controlling terminal */
              listener = polkit_agent_text_listener_new (NULL, &error);
              if (listener == NULL)
                {
                  g_printerr ("Error creating textual authentication agent: %s\n", error->message);
                  g_error_free (error);
                  goto out;
                }
              local_agent_handle = polkit_agent_listener_register (listener,
                                                                   POLKIT_AGENT_REGISTER_FLAGS_RUN_IN_THREAD,
                                                                   subject,
                                                                   NULL, /* object_path */
                                                                   NULL, /* GCancellable */
                                                                   &error);
              g_object_unref (listener);
              if (local_agent_handle == NULL)
                {
                  g_printerr ("Error registering local authentication agent: %s\n", error->message);
                  g_error_free (error);
                  goto out;
                }
              g_object_unref (result);
              result = NULL;
              goto try_again;
            }
          else
            {
              g_printerr ("Authorization requires authentication but no agent is available.\n");
            }
        }
      else
        {
          g_printerr ("Authorization requires authentication and -u wasn't passed.\n");
        }
      ret = 2;
    }
  else if (polkit_authorization_result_get_dismissed (result))
    {
      g_printerr ("Authentication request was dismissed.\n");
      ret = 3;
    }
  else
    {
      g_printerr ("Not authorized.\n");
      ret = 1;
    }

 out:
  /* if applicable, nuke the local authentication agent */
  if (local_agent_handle != NULL)
    polkit_agent_listener_unregister (local_agent_handle);

  if (result != NULL)
    g_object_unref (result);

  g_free (action_id);

  if (details != NULL)
    g_object_unref (details);

  if (subject != NULL)
    g_object_unref (subject);

  if (authority != NULL)
    g_object_unref (authority);

  return ret;
}

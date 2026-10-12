/*
 * Copyright (C) 2026 Amutable
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
 */

/*
 * A proxy that acts on behalf of someone else attaches a tag of the form
 * "<reference>/caller-tag/<provider>" to each connection it makes, and
 * the service passes it to us with the subject.
 *
 * The tag is a lookup key, not a credential: any process may present
 * any tag. What makes it safe is that we verify from kernel credentials
 * that the provider is the subject or at least in its unit (cgroup), so
 * no unrelated process can vouch for a subject.
 *
 * The directory is root-owned and setgid polkitd (see polkit-tmpfiles.conf);
 * a provider creates its socket 0660 so that polkitd can connect to it and
 * nobody else can.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include <polkit/polkit.h>

#include "polkitbackendcallertag.h"

/* FIXME: make this a [CallerTag] ProvidersDirectory= key in polkitd.conf;
 * the environment variable is what the tests use for now. */
#define DEFAULT_PROVIDERS_DIR "/run/polkit-1/caller-tag-providers"
#define PROVIDERS_DIR_ENV     "POLKIT_CALLER_TAG_PROVIDERS_DIR"

/* Defense-in-depth: ensure our opaque handle is big enough that it cannot be guessed */
#define REFERENCE_MIN_LEN 16

/* the tag is a lookup key presented by any bus client, so bound what we
 * are willing to inspect */
#define TAG_MAX_LEN 256

/* synchronous inside check_authorization_sync(): a slow provider stalls
 * every check, so one deadline covers the whole exchange */
#define TIMEOUT_USEC (1000 * 1000)

gboolean
polkit_backend_caller_tag_parse (const gchar  *tag,
                                 gchar       **ret_reference,
                                 gchar       **ret_provider,
                                 GError      **error)
{
  const gchar *slash;
  const gchar *provider;
  const gchar *p;

  if (strnlen (tag, TAG_MAX_LEN + 1) > TAG_MAX_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "tag too long");
      return FALSE;
    }

  slash = strchr (tag, '/');
  if (slash == NULL || slash == tag || !g_str_has_prefix (slash, "/caller-tag/"))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "not a caller tag");
      return FALSE;
    }

  if (slash - tag < REFERENCE_MIN_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "reference is shorter than 64 bits");
      return FALSE;
    }
  for (p = tag; p < slash; p++)
    if (!g_ascii_isxdigit (*p))
      {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "reference is not hex");
        return FALSE;
      }

  /* becomes a path component */
  provider = slash + strlen ("/caller-tag/");
  if (*provider == '\0' || strstr (provider, "..") != NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "bad provider name");
      return FALSE;
    }
  for (p = provider; *p != '\0'; p++)
    if (!g_ascii_isalnum (*p) && *p != '.' && *p != '_' && *p != '-')
      {
        g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "bad provider name");
        return FALSE;
      }

  *ret_reference = g_strndup (tag, slash - tag);
  *ret_provider = g_strdup (provider);
  return TRUE;
}

/* Whoever called listen() on the provider socket must be the subject, or
 * share its cgroup (a unit under systemd), so that prefork and worker-pool
 * providers work but an unrelated process cannot vouch for anyone. */
static gboolean
provider_may_vouch_for (sd_varlink         *link,
                        PolkitUnixProcess  *subject,
                        GError            **error)
{
  int pidfd;
  PolkitSubject *listener = NULL;
  gint listener_pid, subject_pid;
  guint64 listener_cgroup, subject_cgroup;
  gboolean ret = FALSE;

  /* the earlier sd_varlink_connect_address() succeeded even if connect()
   * got EAGAIN because the provider's listen queue was full, which leaves
   * the socket unconnected; the peer query below then fails with ENOTCONN
   * and we refuse at once instead of waiting out the timeout, so a wedged
   * provider does not stall the synchronous path longer than it has to */
  pidfd = sd_varlink_get_peer_pidfd (link);
  if (pidfd < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (-pidfd), "SO_PEERPIDFD: %s", g_strerror (-pidfd));
      return FALSE;
    }
  /* the link owns its pidfd, the subject object closes the one we hand it */
  pidfd = fcntl (pidfd, F_DUPFD_CLOEXEC, 3);
  if (pidfd < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno), "dup pidfd: %s", g_strerror (errno));
      return FALSE;
    }

  listener = polkit_unix_process_new_pidfd (pidfd, -1, NULL);
  listener_pid = polkit_unix_process_get_pid (POLKIT_UNIX_PROCESS (listener));
  subject_pid = polkit_unix_process_get_pid (subject);
  listener_cgroup = polkit_unix_process_get_cgroupid (POLKIT_UNIX_PROCESS (listener));
  subject_cgroup = polkit_unix_process_get_cgroupid (subject);

  /* 0 means unknown or exited; never let two unknowns match */
  if (listener_pid > 0 && listener_pid == subject_pid)
    ret = TRUE;
  else if (listener_cgroup != 0 && listener_cgroup == subject_cgroup)
    ret = TRUE;
  else
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                 "provider pid %d is neither subject pid %d nor in its cgroup",
                 listener_pid, subject_pid);

  g_object_unref (listener);
  return ret;
}

/**
 * polkit_backend_caller_tag_resolve:
 * @tag: The "on-behalf-of" value the service reported.
 * @subject: The subject the tag was reported for.
 * @error: Return location for error.
 *
 * Returns: (transfer full) (nullable): The provider's raw JSON reply, left
 *   for the JS side to parse, or %NULL.
 */
gchar *
polkit_backend_caller_tag_resolve (const gchar        *tag,
                                   PolkitUnixProcess  *subject,
                                   GError            **error)
{
  gchar *reference = NULL;
  gchar *provider = NULL;
  gchar *path = NULL;
  gchar *method = NULL;
  gchar *ret = NULL;
  sd_varlink *link = NULL;
  sd_json_variant *params = NULL;
  sd_json_variant *reply = NULL;
  const gchar *error_id = NULL;
  const gchar *dir;
  gchar *formatted;
  int r;

  g_return_val_if_fail (tag != NULL, NULL);
  g_return_val_if_fail (POLKIT_IS_UNIX_PROCESS (subject), NULL);

  if (!polkit_backend_caller_tag_parse (tag, &reference, &provider, error))
    goto out;

  dir = g_getenv (PROVIDERS_DIR_ENV);
  if (dir == NULL)
    dir = DEFAULT_PROVIDERS_DIR;
  path = g_build_filename (dir, provider, NULL);

  r = sd_varlink_connect_address (&link, path);
  if (r < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (-r), "connect to %s: %s", path, g_strerror (-r));
      goto out;
    }
  (void) sd_varlink_set_relative_timeout (link, TIMEOUT_USEC);

  if (!provider_may_vouch_for (link, subject, error))
    goto out;

  method = g_strdup_printf ("%s.Resolve", provider);
  r = sd_json_buildo (&params, SD_JSON_BUILD_PAIR_STRING ("reference", reference));
  if (r < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (-r), "build request: %s", g_strerror (-r));
      goto out;
    }

  r = sd_varlink_call (link, method, params, &reply, &error_id);
  if (r < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (-r), "%s: %s", method, g_strerror (-r));
      goto out;
    }
  if (error_id != NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "%s: %s", method, error_id);
      goto out;
    }

  /* reply is owned by the link; hand the JS side a string it parses lazily */
  r = sd_json_variant_format (reply, 0, &formatted);
  if (r < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (-r), "format reply: %s", g_strerror (-r));
      goto out;
    }
  ret = g_strdup (formatted);
  free (formatted);

 out:
  sd_json_variant_unref (params);
  sd_varlink_flush_close_unref (link);
  g_free (method);
  g_free (path);
  g_free (provider);
  g_free (reference);
  return ret;
}

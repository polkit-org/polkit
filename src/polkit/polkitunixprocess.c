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

#include <sys/types.h>
#ifdef HAVE_FREEBSD
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "polkitunixprocess.h"
#include "polkitsubject.h"
#include "polkitprivate.h"
#include "polkiterror.h"

/**
 * SECTION:polkitunixprocess
 * @title: PolkitUnixProcess
 * @short_description: Unix processs
 *
 * An object for representing a UNIX process.
 *
 * To uniquely identify processes, both the process id and the start
 * time of the process (a monotonic increasing value representing the
 * time since the kernel was started) is used.
 */

/**
 * PolkitUnixProcess:
 *
 * The #PolkitUnixProcess struct should not be accessed directly.
 */
struct _PolkitUnixProcess
{
  GObject parent_instance;

  gint pid;
  guint64 start_time;
  gint uid;
};

struct _PolkitUnixProcessClass
{
  GObjectClass parent_class;
};

enum
{
  PROP_0,
  PROP_PID,
  PROP_START_TIME,
  PROP_UID
};

static void subject_iface_init (PolkitSubjectIface *subject_iface);

static guint64 get_start_time_for_pid (gint    pid,
                                       GError **error);

static gint _polkit_unix_process_get_owner (PolkitUnixProcess  *process,
                                            GError            **error);

#ifdef HAVE_FREEBSD
static gboolean get_kinfo_proc (gint pid, struct kinfo_proc *p);
#endif

G_DEFINE_TYPE_WITH_CODE (PolkitUnixProcess, polkit_unix_process, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_unix_process_init (PolkitUnixProcess *unix_process)
{
  unix_process->uid = -1;
}

static void
polkit_unix_process_get_property (GObject    *object,
                                  guint       prop_id,
                                  GValue     *value,
                                  GParamSpec *pspec)
{
  PolkitUnixProcess *unix_process = POLKIT_UNIX_PROCESS (object);

  switch (prop_id)
    {
    case PROP_PID:
      g_value_set_int (value, unix_process->pid);
      break;

    case PROP_UID:
      g_value_set_int (value, unix_process->uid);
      break;

    case PROP_START_TIME:
      g_value_set_uint64 (value, unix_process->start_time);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_process_set_property (GObject      *object,
                                  guint         prop_id,
                                  const GValue *value,
                                  GParamSpec   *pspec)
{
  PolkitUnixProcess *unix_process = POLKIT_UNIX_PROCESS (object);

  switch (prop_id)
    {
    case PROP_PID:
      polkit_unix_process_set_pid (unix_process, g_value_get_int (value));
      break;

    case PROP_UID:
      polkit_unix_process_set_uid (unix_process, g_value_get_int (value));
      break;

    case PROP_START_TIME:
      polkit_unix_process_set_start_time (unix_process, g_value_get_uint64 (value));
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_process_constructed (GObject *object)
{
  PolkitUnixProcess *process = POLKIT_UNIX_PROCESS (object);

  /* sets start_time and uid in case they are unset */

  if (process->start_time == 0)
    process->start_time = get_start_time_for_pid (process->pid, NULL);

  if (process->uid == -1)
    {
      GError *error;
      error = NULL;
      process->uid = _polkit_unix_process_get_owner (process, &error);
      if (error != NULL)
        {
          process->uid = -1;
          g_error_free (error);
        }
    }

  if (G_OBJECT_CLASS (polkit_unix_process_parent_class)->constructed != NULL)
    G_OBJECT_CLASS (polkit_unix_process_parent_class)->constructed (object);
}

static void
polkit_unix_process_class_init (PolkitUnixProcessClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_unix_process_get_property;
  gobject_class->set_property = polkit_unix_process_set_property;
  gobject_class->constructed =  polkit_unix_process_constructed;

  /**
   * PolkitUnixProcess:pid:
   *
   * The UNIX process id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_PID,
                                   g_param_spec_int ("pid",
                                                     "Process ID",
                                                     "The UNIX process ID",
                                                     0,
                                                     G_MAXINT,
                                                     0,
                                                     G_PARAM_CONSTRUCT |
                                                     G_PARAM_READWRITE |
                                                     G_PARAM_STATIC_NAME |
                                                     G_PARAM_STATIC_BLURB |
                                                     G_PARAM_STATIC_NICK));

  /**
   * PolkitUnixProcess:uid:
   *
   * The UNIX user id of the process or -1 if unknown.
   *
   * Note that this is the real user-id, not the effective user-id.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_UID,
                                   g_param_spec_int ("uid",
                                                     "User ID",
                                                     "The UNIX user ID",
                                                     -1,
                                                     G_MAXINT,
                                                     -1,
                                                     G_PARAM_CONSTRUCT |
                                                     G_PARAM_READWRITE |
                                                     G_PARAM_STATIC_NAME |
                                                     G_PARAM_STATIC_BLURB |
                                                     G_PARAM_STATIC_NICK));

  /**
   * PolkitUnixProcess:start-time:
   *
   * The start time of the process.
   */
  g_object_class_install_property (gobject_class,
                                   PROP_START_TIME,
                                   g_param_spec_uint64 ("start-time",
                                                        "Start Time",
                                                        "The start time of the process, since the machine booted",
                                                        0,
                                                        G_MAXUINT64,
                                                        0,
                                                        G_PARAM_CONSTRUCT |
                                                        G_PARAM_READWRITE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

}

/**
 * polkit_unix_process_get_uid:
 * @process: A #PolkitUnixProcess.
 *
 * Gets the user id for @process. Note that this is the real user-id,
 * not the effective user-id.
 *
 * Returns: The user id for @process or -1 if unknown.
 */
gint
polkit_unix_process_get_uid (PolkitUnixProcess *process)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_PROCESS (process), -1);
  return process->uid;
}

/**
 * polkit_unix_process_set_uid:
 * @process: A #PolkitUnixProcess.
 * @uid: The user id to set for @process or -1 to unset it.
 *
 * Sets the (real, not effective) user id for @process.
 */
void
polkit_unix_process_set_uid (PolkitUnixProcess *process,
                             gint               uid)
{
  g_return_if_fail (POLKIT_IS_UNIX_PROCESS (process));
  g_return_if_fail (uid >= -1);
  process->uid = uid;
}

/**
 * polkit_unix_process_get_pid:
 * @process: A #PolkitUnixProcess.
 *
 * Gets the process id for @process.
 *
 * Returns: The process id for @process.
 */
gint
polkit_unix_process_get_pid (PolkitUnixProcess *process)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_PROCESS (process), 0);
  return process->pid;
}

/**
 * polkit_unix_process_get_start_time:
 * @process: A #PolkitUnixProcess.
 *
 * Gets the start time of @process.
 *
 * Returns: The start time of @process.
 */
guint64
polkit_unix_process_get_start_time (PolkitUnixProcess *process)
{
  g_return_val_if_fail (POLKIT_IS_UNIX_PROCESS (process), 0);
  return process->start_time;
}

/**
 * polkit_unix_process_set_start_time:
 * @process: A #PolkitUnixProcess.
 * @start_time: The start time for @pid.
 *
 * Set the start time of @process.
 */
void
polkit_unix_process_set_start_time (PolkitUnixProcess *process,
                                    guint64            start_time)
{
  g_return_if_fail (POLKIT_IS_UNIX_PROCESS (process));
  process->start_time = start_time;
}

/**
 * polkit_unix_process_set_pid:
 * @process: A #PolkitUnixProcess.
 * @pid: A process id.
 *
 * Sets @pid for @process.
 */
void
polkit_unix_process_set_pid (PolkitUnixProcess *process,
                             gint              pid)
{
  g_return_if_fail (POLKIT_IS_UNIX_PROCESS (process));
  process->pid = pid;
}

/**
 * polkit_unix_process_new:
 * @pid: The process id.
 *
 * Creates a new #PolkitUnixProcess for @pid.
 *
 * The uid and start time of the process will be looked up in using
 * e.g. the <filename>/proc</filename> filesystem depending on the
 * platform in use.
 *
 * Returns: (transfer full): A #PolkitSubject. Free with g_object_unref().
 */
PolkitSubject *
polkit_unix_process_new (gint pid)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_PROCESS,
                                       "pid", pid,
                                       NULL));
}

/**
 * polkit_unix_process_new_full:
 * @pid: The process id.
 * @start_time: The start time for @pid.
 *
 * Creates a new #PolkitUnixProcess object for @pid and @start_time.
 *
 * The uid of the process will be looked up in using e.g. the
 * <filename>/proc</filename> filesystem depending on the platform in
 * use.
 *
 * Returns: (transfer full): A #PolkitSubject. Free with g_object_unref().
 */
PolkitSubject *
polkit_unix_process_new_full (gint pid,
                              guint64 start_time)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_PROCESS,
                                       "pid", pid,
                                       "start_time", start_time,
                                       NULL));
}

/**
 * polkit_unix_process_new_for_owner:
 * @pid: The process id.
 * @start_time: The start time for @pid or 0 to look it up in e.g. <filename>/proc</filename>.
 * @uid: The (real, not effective) uid of the owner of @pid or -1 to look it up in e.g. <filename>/proc</filename>.
 *
 * Creates a new #PolkitUnixProcess object for @pid, @start_time and @uid.
 *
 * Returns: (transfer full): A #PolkitSubject. Free with g_object_unref().
 */
PolkitSubject *
polkit_unix_process_new_for_owner (gint    pid,
                                   guint64 start_time,
                                   gint    uid)
{
  return POLKIT_SUBJECT (g_object_new (POLKIT_TYPE_UNIX_PROCESS,
                                       "pid", pid,
                                       "start_time", start_time,
                                       "uid", uid,
                                       NULL));
}

static guint
polkit_unix_process_hash (PolkitSubject *subject)
{
  PolkitUnixProcess *process = POLKIT_UNIX_PROCESS (subject);

  return g_direct_hash (GSIZE_TO_POINTER ((process->pid + process->start_time))) ;
}

static gboolean
polkit_unix_process_equal (PolkitSubject *a,
                        PolkitSubject *b)
{
  PolkitUnixProcess *process_a;
  PolkitUnixProcess *process_b;

  process_a = POLKIT_UNIX_PROCESS (a);
  process_b = POLKIT_UNIX_PROCESS (b);

  return
    (process_a->pid == process_b->pid) &&
    (process_a->start_time == process_b->start_time);
}

static gchar *
polkit_unix_process_to_string (PolkitSubject *subject)
{
  PolkitUnixProcess *process = POLKIT_UNIX_PROCESS (subject);

  return g_strdup_printf ("unix-process:%d:%" G_GUINT64_FORMAT, process->pid, process->start_time);
}

static gboolean
polkit_unix_process_exists_sync (PolkitSubject   *subject,
                                 GCancellable    *cancellable,
                                 GError         **error)
{
  PolkitUnixProcess *process = POLKIT_UNIX_PROCESS (subject);
  GError *local_error;
  guint64 start_time;
  gboolean ret;

  ret = TRUE;

  local_error = NULL;
  start_time = get_start_time_for_pid (process->pid, &local_error);
  if (local_error != NULL)
    {
      /* Don't propagate the error - it just means there is no process with this pid */
      g_error_free (local_error);
      ret = FALSE;
    }
  else
    {
      if (start_time != process->start_time)
        {
          ret = FALSE;
        }
    }

  return ret;
}

static void
polkit_unix_process_exists (PolkitSubject       *subject,
                            GCancellable        *cancellable,
                            GAsyncReadyCallback  callback,
                            gpointer             user_data)
{
  GSimpleAsyncResult *simple;
  simple = g_simple_async_result_new (G_OBJECT (subject),
                                      callback,
                                      user_data,
                                      polkit_unix_process_exists);
  g_simple_async_result_complete (simple);
  g_object_unref (simple);
}

static gboolean
polkit_unix_process_exists_finish (PolkitSubject  *subject,
                                   GAsyncResult   *res,
                                   GError        **error)
{
  GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (res);

  g_warn_if_fail (g_simple_async_result_get_source_tag (simple) == polkit_unix_process_exists);

  return polkit_unix_process_exists_sync (subject,
                                          NULL,
                                          error);
}


static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->hash          = polkit_unix_process_hash;
  subject_iface->equal         = polkit_unix_process_equal;
  subject_iface->to_string     = polkit_unix_process_to_string;
  subject_iface->exists        = polkit_unix_process_exists;
  subject_iface->exists_finish = polkit_unix_process_exists_finish;
  subject_iface->exists_sync   = polkit_unix_process_exists_sync;
}

#ifdef HAVE_SOLARIS
static int
get_pid_psinfo (pid_t pid, struct psinfo *ps)
{
  char pname[32];
  int  procfd;

  (void) snprintf(pname, sizeof(pname), "/proc/%d/psinfo", pid);
  if ((procfd = open(pname, O_RDONLY)) == -1)
    {
      return -1;
    }
  if (read(procfd, ps, sizeof(struct psinfo)) < 0)
    {
      (void) close(procfd);
      return -1;
    }
  (void) close(procfd);
  return 0;
}
#endif

#ifdef HAVE_FREEBSD
static gboolean
get_kinfo_proc (pid_t pid, struct kinfo_proc *p)
{
  int mib[4];
  size_t len;

  len = 4;
  sysctlnametomib ("kern.proc.pid", mib, &len);

  len = sizeof (struct kinfo_proc);
  mib[3] = pid;

  if (sysctl (mib, 4, p, &len, NULL, 0) == -1)
    return FALSE;

  return TRUE;
}
#endif

static guint64
get_start_time_for_pid (pid_t    pid,
                        GError **error)
{
  guint64 start_time;
#ifndef HAVE_FREEBSD
  gchar *filename;
  gchar *contents;
  size_t length;
  gchar **tokens;
  guint num_tokens;
  gchar *p;
  gchar *endp;

  start_time = 0;
  contents = NULL;

  filename = g_strdup_printf ("/proc/%d/stat", pid);

  if (!g_file_get_contents (filename, &contents, &length, error))
    goto out;

  /* start time is the token at index 19 after the '(process name)' entry - since only this
   * field can contain the ')' character, search backwards for this to avoid malicious
   * processes trying to fool us
   */
  p = strrchr (contents, ')');
  if (p == NULL)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error parsing file %s",
                   filename);
      goto out;
    }
  p += 2; /* skip ') ' */
  if (p - contents >= (int) length)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error parsing file %s",
                   filename);
      goto out;
    }

  tokens = g_strsplit (p, " ", 0);

  num_tokens = g_strv_length (tokens);

  if (num_tokens < 20)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error parsing file %s",
                   filename);
      goto out;
    }

  start_time = strtoull (tokens[19], &endp, 10);
  if (endp == tokens[19])
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error parsing file %s",
                   filename);
      goto out;
    }

  g_strfreev (tokens);

 out:
  g_free (filename);
  g_free (contents);
#else
  struct kinfo_proc p;

  start_time = 0;

  if (! get_kinfo_proc (pid, &p))
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "Error obtaining start time for %d (%s)",
                   (gint) pid,
                   g_strerror (errno));
      goto out;
    }

  start_time = (guint64) p.ki_start.tv_sec;

out:
#endif

  return start_time;
}

static gint
_polkit_unix_process_get_owner (PolkitUnixProcess  *process,
                                GError            **error)
{
  gint result;
  gchar *contents;
  gchar **lines;
#ifdef HAVE_FREEBSD
  struct kinfo_proc p;
#else
  gchar filename[64];
  guint n;
#endif

  g_return_val_if_fail (POLKIT_IS_UNIX_PROCESS (process), 0);
  g_return_val_if_fail (error == NULL || *error == NULL, 0);

  result = 0;
  lines = NULL;
  contents = NULL;

#ifdef HAVE_FREEBSD
  if (get_kinfo_proc (process->pid, &p) == 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "get_kinfo_proc() failed for pid %d: %s",
                   process->pid,
                   g_strerror (errno));
      goto out;
    }

  result = p.ki_uid;
#else

  /* see 'man proc' for layout of the status file
   *
   * Uid, Gid: Real, effective, saved set,  and  file  system  UIDs (GIDs).
   */
  g_snprintf (filename, sizeof filename, "/proc/%d/status", process->pid);
  if (!g_file_get_contents (filename,
                            &contents,
                            NULL,
                            error))
    {
      goto out;
    }
  lines = g_strsplit (contents, "\n", -1);
  for (n = 0; lines != NULL && lines[n] != NULL; n++)
    {
      gint real_uid, effective_uid;
      if (!g_str_has_prefix (lines[n], "Uid:"))
        continue;
      if (sscanf (lines[n] + 4, "%d %d", &real_uid, &effective_uid) != 2)
        {
          g_set_error (error,
                       POLKIT_ERROR,
                       POLKIT_ERROR_FAILED,
                       "Unexpected line `%s' in file %s",
                       lines[n],
                       filename);
          goto out;
        }
      else
        {
          result = real_uid;
          goto out;
        }
    }

  g_set_error (error,
               POLKIT_ERROR,
               POLKIT_ERROR_FAILED,
               "Didn't find any line starting with `Uid:' in file %s",
               filename);
#endif

out:
  g_strfreev (lines);
  g_free (contents);
  return result;
}

/* deprecated public method */
gint
polkit_unix_process_get_owner (PolkitUnixProcess  *process,
                               GError            **error)
{
  return _polkit_unix_process_get_owner (process, error);
}

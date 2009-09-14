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
#ifndef HAVE_FREEBSD
#include <sys/stat.h>
#else
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
};

static void subject_iface_init (PolkitSubjectIface *subject_iface);

static guint64 get_start_time_for_pid (gint    pid,
                                       GError **error);

#ifdef HAVE_FREEBSD
static gboolean get_kinfo_proc (gint pid, struct kinfo_proc *p);
#endif

G_DEFINE_TYPE_WITH_CODE (PolkitUnixProcess, polkit_unix_process, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (POLKIT_TYPE_SUBJECT, subject_iface_init)
                         );

static void
polkit_unix_process_init (PolkitUnixProcess *unix_process)
{
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

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static void
polkit_unix_process_class_init (PolkitUnixProcessClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->get_property = polkit_unix_process_get_property;
  gobject_class->set_property = polkit_unix_process_set_property;

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
                                                        G_PARAM_READABLE |
                                                        G_PARAM_STATIC_NAME |
                                                        G_PARAM_STATIC_BLURB |
                                                        G_PARAM_STATIC_NICK));

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
  return process->pid;
}

/**
 * polkit_unix_process_get_owner:
 * @process: A #PolkitUnixProcess.
 * @error: Return location for error or %NULL.
 *
 * Gets the uid of the owner of @process.
 *
 * Returns: The UNIX user id of the owner for @process or 0 if @error is set.
 **/
gint
polkit_unix_process_get_owner (PolkitUnixProcess  *process,
                               GError            **error)
{
  gint result;
#ifdef HAVE_FREEBSD
  struct kinfo_proc p;
#else
  struct stat statbuf;
  char procbuf[32];
#endif

  result = 0;

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
  g_snprintf (procbuf, sizeof procbuf, "/proc/%d", process->pid);
  if (stat (procbuf, &statbuf) != 0)
    {
      g_set_error (error,
                   POLKIT_ERROR,
                   POLKIT_ERROR_FAILED,
                   "stat() failed for /proc/%d: %s",
                   process->pid,
                   g_strerror (errno));
      goto out;
    }

  result = statbuf.st_uid;
#endif

 out:

  return result;
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
  return process->start_time;
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
  process->pid = pid;
  if (pid != (gint) -1)
    process->start_time = get_start_time_for_pid (pid, NULL);
}

/**
 * polkit_unix_process_new:
 * @pid: The process id.
 *
 * Creates a new #PolkitUnixProcess for @pid. The start time of the
 * process will be looked up in using e.g. the
 * <filename>/proc</filename> filesystem depending on the platform in
 * use.
 *
 * Returns: A #PolkitSubject. Free with g_object_unref().
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
 * Returns: A #PolkitSubject. Free with g_object_unref().
 */
PolkitSubject *
polkit_unix_process_new_full (gint pid,
                              guint64 start_time)
{
  PolkitUnixProcess *process;

  process = POLKIT_UNIX_PROCESS (polkit_unix_process_new ((gint) -1));
  process->pid = pid;
  process->start_time = start_time;

  return POLKIT_SUBJECT (process);
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

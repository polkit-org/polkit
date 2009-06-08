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

#include <stdlib.h>
#include <string.h>
#include "polkitunixprocess.h"
#include "polkitsubject.h"
#include "polkitprivate.h"

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

  pid_t pid;
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

static guint64 get_start_time_for_pid (pid_t pid);

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
      g_value_set_uint (value, unix_process->pid);
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
      polkit_unix_process_set_pid (unix_process, g_value_get_uint (value));
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
                                   g_param_spec_uint ("pid",
                                                      "Process ID",
                                                      "The UNIX process ID",
                                                      0,
                                                      G_MAXUINT,
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
pid_t
polkit_unix_process_get_pid (PolkitUnixProcess *process)
{
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
                             pid_t              pid)
{
  process->pid = pid;
  if (pid != (pid_t) -1)
    process->start_time = get_start_time_for_pid (pid);
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
polkit_unix_process_new (pid_t pid)
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
polkit_unix_process_new_full (pid_t pid,
                              guint64 start_time)
{
  PolkitUnixProcess *process;

  process = POLKIT_UNIX_PROCESS (polkit_unix_process_new ((pid_t) -1));
  process->pid = pid;
  process->start_time = start_time;

  return POLKIT_SUBJECT (process);
}

static guint
polkit_unix_process_hash (PolkitSubject *subject)
{
  PolkitUnixProcess *process = POLKIT_UNIX_PROCESS (subject);

  return g_direct_hash (GINT_TO_POINTER ((process->pid + process->start_time))) ;
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

static void
subject_iface_init (PolkitSubjectIface *subject_iface)
{
  subject_iface->hash      = polkit_unix_process_hash;
  subject_iface->equal     = polkit_unix_process_equal;
  subject_iface->to_string = polkit_unix_process_to_string;
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

static guint64
get_start_time_for_pid (pid_t pid)
{
  gchar *filename;
  gchar *contents;
  size_t length;
  guint64 start_time;
  GError *error;
#ifdef HAVE_SOLARIS
  struct psinfo info;
#else
  gchar **tokens;
  guint num_tokens;
  gchar *p;
  gchar *endp;
#endif

  start_time = 0;
  contents = NULL;

#ifdef HAVE_SOLARIS
  if (polkit_sysdeps_pid_psinfo (pid, &info))
    {
      goto out;
    }
  start_time = (unsigned long long) (info.pr_start.tv_sec);
#else
#ifdef __FreeBSD__
  filename = g_strdup_printf ("/proc/%d/status", pid);
#else
  filename = g_strdup_printf ("/proc/%d/stat", pid);
#endif

  error = NULL;
  if (!g_file_get_contents (filename, &contents, &length, &error))
    {
      g_warning ("Cannot get contents of '%s': %s\n", filename, error->message);
      goto out;
    }

#ifdef __FreeBSD__
  tokens = kit_strsplit (contents, " ", &num_tokens);
  if (tokens == NULL)
    goto out;

  if (num_tokens < 8)
    {
      g_strfreev (tokens);
      goto out;
    }

  p = g_strdup (tokens[7]);
  g_strfreev (tokens);

  tokens = g_strsplit (p, ",", 0);
  g_free (p);

  if (tokens == NULL)
    goto out;

  num_tokens = g_strv_length (tokens);

  if (num_tokens >= 1)
    {
      start_time = strtoll (tokens[0], &endp, 10);
      if (endp == tokens[0])
        {
          g_strfreev (tokens);
          goto out;
        }
    }
  else
    {
      g_strfreev (tokens);
      goto out;
    }

  g_strfreev (tokens);

#else

    /* start time is the 19th token after the '(process name)' entry */
  p = strchr (contents, ')');
  if (p == NULL)
    {
      goto out;
    }
  p += 2; /* skip ') ' */
  if (p - contents >= (int) length)
    {
      goto out;
    }

  tokens = g_strsplit (p, " ", 0);

  if (tokens == NULL)
    goto out;

  num_tokens = g_strv_length (tokens);

  if (num_tokens < 20)
    goto out;

  start_time = strtoll (tokens[19], &endp, 10);
  if (endp == tokens[19])
    goto out;

  g_strfreev (tokens);
#endif
#endif

 out:
#ifndef HAVE_SOLARIS
  g_free (filename);
  g_free (contents);
#endif

  if (start_time == 0)
    {
      g_warning ("Cannot lookup start-time for pid %d", pid);
    }

  return start_time;
}

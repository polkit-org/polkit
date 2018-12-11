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
#ifdef HAVE_NETBSD
#include <sys/param.h>
#include <sys/sysctl.h>
#endif
#ifdef HAVE_OPENBSD
#include <sys/sysctl.h>
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
 * An object for representing a UNIX process.  NOTE: This object as
 * designed is now known broken; a mechanism to exploit a delay in
 * start time in the Linux kernel was identified.  Avoid
 * calling polkit_subject_equal() to compare two processes.
 *
 * To uniquely identify processes, both the process id and the start
 * time of the process (a monotonic increasing value representing the
 * time since the kernel was started) is used.
 *
 * NOTE: This object stores, and provides access to, the real UID of the
 * process.  That value can change over time (with set*uid*(2) and exec*(2)).
 * Checks whether an operation is allowed need to take care to use the UID
 * value as of the time when the operation was made (or, following the open()
 * privilege check model, when the connection making the operation possible
 * was initiated).  That is usually done by initializing this with
 * polkit_unix_process_new_for_owner() with trusted data.
 */

/* See https://gitlab.freedesktop.org/polkit/polkit/issues/75

  But quoting the original email in full here to ensure it's preserved:

  From: Jann Horn <jannh@google.com>
  Subject: [SECURITY] polkit: temporary auth hijacking via PID reuse and non-atomic fork
  Date: Wednesday, October 10, 2018 5:34 PM

When a (non-root) user attempts to e.g. control systemd units in the system
instance from an active session over DBus, the access is gated by a polkit
policy that requires "auth_admin_keep" auth. This results in an auth prompt
being shown to the user, asking the user to confirm the action by entering the
password of an administrator account.

After the action has been confirmed, the auth decision for "auth_admin_keep" is
cached for up to five minutes. Subject to some restrictions, similar actions can
then be performed in this timespan without requiring re-auth:

 - The PID of the DBus client requesting the new action must match the PID of
   the DBus client requesting the old action (based on SO_PEERCRED information
   forwarded by the DBus daemon).
 - The "start time" of the client's PID (as seen in /proc/$pid/stat, field 22)
   must not have changed. The granularity of this timestamp is in the
   millisecond range.
 - polkit polls every two seconds whether a process with the expected start time
   still exists. If not, the temporary auth entry is purged.

Without the start time check, this would obviously be buggy because an attacker
could simply wait for the legitimate client to disappear, then create a new
client with the same PID.

Unfortunately, the start time check is bypassable because fork() is not atomic.
Looking at the source code of copy_process() in the kernel:

        p->start_time = ktime_get_ns();
        p->real_start_time = ktime_get_boot_ns();
        [...]
        retval = copy_thread_tls(clone_flags, stack_start, stack_size, p, tls);
        if (retval)
                goto bad_fork_cleanup_io;

        if (pid != &init_struct_pid) {
                pid = alloc_pid(p->nsproxy->pid_ns_for_children);
                if (IS_ERR(pid)) {
                        retval = PTR_ERR(pid);
                        goto bad_fork_cleanup_thread;
                }
        }

The ktime_get_boot_ns() call is where the "start time" of the process is
recorded. The alloc_pid() call is where a free PID is allocated. In between
these, some time passes; and because the copy_thread_tls() call between them can
access userspace memory when sys_clone() is invoked through the 32-bit syscall
entry point, an attacker can even stall the kernel arbitrarily long at this
point (by supplying a pointer into userspace memory that is associated with a
userfaultfd or is backed by a custom FUSE filesystem).

This means that an attacker can immediately call sys_clone() when the victim
process is created, often resulting in a process that has the exact same start
time reported in procfs; and then the attacker can delay the alloc_pid() call
until after the victim process has died and the PID assignment has cycled
around. This results in an attacker process that polkit can't distinguish from
the victim process.
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

#if defined(HAVE_FREEBSD) || defined(HAVE_NETBSD) || defined(HAVE_OPENBSD)
static gboolean get_kinfo_proc (gint pid,
#if defined(HAVE_NETBSD)
                                struct kinfo_proc2 *p);
#else
                                struct kinfo_proc *p);
#endif
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
      process->uid = polkit_unix_process_get_racy_uid__ (process, &error);
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
                                                     G_MININT,
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
 * NOTE: The UID may change over time, so the returned value may not match the
 * current state of the underlying process; or the UID may have been set by
 * polkit_unix_process_new_for_owner() or polkit_unix_process_set_uid(),
 * in which case it may not correspond to the actual UID of the referenced
 * process at all (at any point in time).
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

#if defined(HAVE_NETBSD) || defined(HAVE_OPENBSD)
static gboolean
get_kinfo_proc (gint pid,
#ifdef HAVE_NETBSD
                struct kinfo_proc2 *p)
#else
                struct kinfo_proc *p)
#endif
{
  int name[6];
  u_int namelen;
  size_t sz;

  sz = sizeof(*p);
  namelen = 0;
  name[namelen++] = CTL_KERN;
#ifdef HAVE_NETBSD
  name[namelen++] = KERN_PROC2;
#else
  name[namelen++] = KERN_PROC;
#endif
  name[namelen++] = KERN_PROC_PID;
  name[namelen++] = pid;
  name[namelen++] = sz;
  name[namelen++] = 1;

  if (sysctl (name, namelen, p, &sz, NULL, 0) == -1)
    return FALSE;

  return TRUE;
}
#endif

static guint64
get_start_time_for_pid (pid_t    pid,
                        GError **error)
{
  guint64 start_time;
#if !defined(HAVE_FREEBSD) && !defined(HAVE_NETBSD) && !defined(HAVE_OPENBSD)
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
#ifdef HAVE_NETBSD
  struct kinfo_proc2 p;
#else
  struct kinfo_proc p;
#endif

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

#ifdef HAVE_FREEBSD
  start_time = (guint64) p.ki_start.tv_sec;
#else
  start_time = (guint64) p.p_ustart_sec;
#endif

out:
#endif

  return start_time;
}

/*
 * Private: Return the "current" UID.  Note that this is inherently racy,
 * and the value may already be obsolete by the time this function returns;
 * this function only guarantees that the UID was valid at some point during
 * its execution.
 */
gint
polkit_unix_process_get_racy_uid__ (PolkitUnixProcess  *process,
                                    GError            **error)
{
  gint result;
  gchar *contents;
  gchar **lines;
  guint64 start_time;
#if defined(HAVE_FREEBSD) || defined(HAVE_OPENBSD)
  struct kinfo_proc p;
#elif defined(HAVE_NETBSD)
  struct kinfo_proc2 p;
#else
  gchar filename[64];
  guint n;
  GError *local_error;
#endif

  g_return_val_if_fail (POLKIT_IS_UNIX_PROCESS (process), 0);
  g_return_val_if_fail (error == NULL || *error == NULL, 0);

  result = 0;
  lines = NULL;
  contents = NULL;

#if defined(HAVE_FREEBSD) || defined(HAVE_NETBSD) || defined(HAVE_OPENBSD)
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

#if defined(HAVE_FREEBSD)
  result = p.ki_uid;
  start_time = (guint64) p.ki_start.tv_sec;
#else
  result = p.p_uid;
  start_time = (guint64) p.p_ustart_sec;
#endif
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
          goto found;
        }
    }
  g_set_error (error,
               POLKIT_ERROR,
               POLKIT_ERROR_FAILED,
               "Didn't find any line starting with `Uid:' in file %s",
               filename);
  goto out;

found:
  /* The UID and start time are, sadly, not available in a single file.  So,
   * read the UID first, and then the start time; if the start time is the same
   * before and after reading the UID, it couldn't have changed.
   */
  local_error = NULL;
  start_time = get_start_time_for_pid (process->pid, &local_error);
  if (local_error != NULL)
    {
      g_propagate_error (error, local_error);
      goto out;
    }
#endif

  if (process->start_time != start_time)
    {
      g_set_error (error, POLKIT_ERROR, POLKIT_ERROR_FAILED,
		   "process with PID %d has been replaced", process->pid);
      goto out;
    }

out:
  g_strfreev (lines);
  g_free (contents);
  return result;
}

/* deprecated public method */
/**
 * polkit_unix_process_get_owner:
 * @process: A #PolkitUnixProcess.
 * @error: Return location for error.
 *
 * (deprecated)
 */
gint
polkit_unix_process_get_owner (PolkitUnixProcess  *process,
                               GError            **error)
{
  return polkit_unix_process_get_racy_uid__ (process, error);
}

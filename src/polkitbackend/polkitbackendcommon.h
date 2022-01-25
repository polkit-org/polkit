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

#if !defined (_POLKIT_BACKEND_COMPILATION) && !defined(_POLKIT_BACKEND_INSIDE_POLKIT_BACKEND_H)
#error "Only <polkitbackend/polkitbackend.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef __POLKIT_BACKEND_COMMON_H
#define __POLKIT_BACKEND_COMMON_H

#include "config.h"
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_NETGROUP_H
#include <netgroup.h>
#else
#include <netdb.h>
#endif
#include <string.h>
#include <glib/gstdio.h>
#include <locale.h>
#include <glib/gi18n-lib.h> //here, all things glib via glib.h (including -> gspawn.h)

#include <polkit/polkit.h>
#include "polkitbackendjsauthority.h"

#include <polkit/polkitprivate.h>

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-login.h>
#endif /* HAVE_LIBSYSTEMD */

#define RUNAWAY_KILLER_TIMEOUT (15)

#ifdef __cplusplus
extern "C" {
#endif

enum
{
  PROP_0,
  PROP_RULES_DIRS,
};

typedef struct
{
  GSimpleAsyncResult *simple; /* borrowed reference */
  GMainContext *main_context; /* may be NULL */

  GCancellable *cancellable;  /* may be NULL */
  gulong cancellable_handler_id;

  GPid child_pid;
  gint child_stdout_fd;
  gint child_stderr_fd;

  GIOChannel *child_stdout_channel;
  GIOChannel *child_stderr_channel;

  GSource *child_watch_source;
  GSource *child_stdout_source;
  GSource *child_stderr_source;

  guint timeout_seconds;
  gboolean timed_out;
  GSource *timeout_source;

  GString *child_stdout;
  GString *child_stderr;

  gint exit_status;
} UtilsSpawnData;

typedef struct
{
  GMainLoop *loop;
  GAsyncResult *res;
} SpawnData;

void polkit_backend_common_spawn (const gchar *const  *argv,
                                  guint                timeout_seconds,
                                  GCancellable        *cancellable,
                                  GAsyncReadyCallback  callback,
                                  gpointer             user_data);
void polkit_backend_common_spawn_cb (GObject       *source_object,
                                     GAsyncResult  *res,
                                     gpointer       user_data);
gboolean polkit_backend_common_spawn_finish (GAsyncResult   *res,
                                             gint           *out_exit_status,
                                             gchar         **out_standard_output,
                                             gchar         **out_standard_error,
                                             GError        **error);

void polkit_backend_common_on_dir_monitor_changed (GFileMonitor     *monitor,
                                                   GFile            *file,
                                                   GFile            *other_file,
                                                   GFileMonitorEvent event_type,
                                                   gpointer          user_data);

void polkit_backend_common_js_authority_class_init_common (PolkitBackendJsAuthorityClass *klass);

gint polkit_backend_common_rules_file_name_cmp (const gchar *a,
                                                const gchar *b);

const gchar *polkit_backend_common_get_signal_name (gint signal_number);

/* To be provided by each JS backend, from here onwards  ---------------------------------------------- */

void polkit_backend_common_reload_scripts (PolkitBackendJsAuthority *authority);
void polkit_backend_common_js_authority_finalize (GObject *object);
void polkit_backend_common_js_authority_constructed (GObject *object);
GList *polkit_backend_common_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *_authority,
                                                                     PolkitSubject                     *caller,
                                                                     PolkitSubject                     *subject,
                                                                     PolkitIdentity                    *user_for_subject,
                                                                     gboolean                           subject_is_local,
                                                                     gboolean                           subject_is_active,
                                                                     const gchar                       *action_id,
                                                                     PolkitDetails                     *details);
void polkit_backend_common_js_authority_set_property (GObject      *object,
                                                      guint         property_id,
                                                      const GValue *value,
                                                      GParamSpec   *pspec);
PolkitImplicitAuthorization polkit_backend_common_js_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *_authority,
                                                                                         PolkitSubject                     *caller,
                                                                                         PolkitSubject                     *subject,
                                                                                         PolkitIdentity                    *user_for_subject,
                                                                                         gboolean                           subject_is_local,
                                                                                         gboolean                           subject_is_active,
                                                                                         const gchar                       *action_id,
                                                                                         PolkitDetails                     *details,
                                                                                         PolkitImplicitAuthorization        implicit);
#ifdef __cplusplus
}
#endif

#endif /* __POLKIT_BACKEND_COMMON_H */


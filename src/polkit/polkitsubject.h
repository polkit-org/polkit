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

#ifndef __POLKIT_SUBJECT_H
#define __POLKIT_SUBJECT_H

#include <sys/types.h>
#include <unistd.h>
#include <glib-object.h>
#include <polkit/polkitbindings.h>

G_BEGIN_DECLS

#define POLKIT_TYPE_SUBJECT         (polkit_subject_get_type())
#define POLKIT_SUBJECT(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_SUBJECT, PolkitSubject))
#define POLKIT_IS_SUBJECT(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_SUBJECT))
#define POLKIT_SUBJECT_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE((o), POLKIT_TYPE_SUBJECT, PolkitSubjectIface))

#if 0
typedef struct _PolkitSubject PolkitSubject; /* Dummy typedef */
#endif
typedef struct _PolkitSubjectIface PolkitSubjectIface;

typedef enum
{
  POLKIT_SUBJECT_KIND_UNIX_PROCESS,
  POLKIT_SUBJECT_KIND_UNIX_USER,
  POLKIT_SUBJECT_KIND_UNIX_GROUP,
} PolkitSubjectKind;

struct _PolkitSubjectIface
{
  GTypeInterface g_iface;
};

GType              polkit_subject_get_type              (void) G_GNUC_CONST;
PolkitSubject     *polkit_subject_new_for_unix_process  (pid_t          unix_process_id);
PolkitSubject     *polkit_subject_new_for_unix_user     (uid_t          unix_user_id);
PolkitSubject     *polkit_subject_new_for_unix_group    (gid_t          unix_group_id);
PolkitSubjectKind  polkit_subject_get_kind              (PolkitSubject *subject);
pid_t              polkit_subject_unix_process_get_id   (PolkitSubject *subject);
uid_t              polkit_subject_unix_user_get_id      (PolkitSubject *subject);
gid_t              polkit_subject_unix_group_get_id     (PolkitSubject *subject);
gboolean           polkit_subject_equal                 (PolkitSubject *a,
                                                         PolkitSubject *b);

G_END_DECLS

#endif /* __POLKIT_SUBJECT_H */

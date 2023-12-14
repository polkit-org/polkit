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

#ifndef __POLKIT_PRIVATE_H
#define __POLKIT_PRIVATE_H

#include "polkitimplicitauthorization.h"
#include "polkitactiondescription.h"
#include "polkitsubject.h"
#include "polkitauthorizationresult.h"
#include "polkittemporaryauthorization.h"

/* FIXME: This header file is currently installed among other public header
   files, and the symbols are exported in the shared library.

   For application writers: relying on any function here is strongly
   discouraged.

   For polkit maintainers: This should be made private if a large ABI break
   were necessary in the future.  In the meantime, consider that there is
   non-zero risk that changing these functions might break some applications. */

PolkitActionDescription  *polkit_action_description_new_for_gvariant (GVariant *value);
GVariant *polkit_action_description_to_gvariant (PolkitActionDescription *action_description);

GVariant *polkit_subject_to_gvariant (PolkitSubject *subject);
GVariant *polkit_identity_to_gvariant (PolkitIdentity *identity);

gint polkit_unix_process_get_racy_uid__ (PolkitUnixProcess *process, GError **error);

PolkitSubject  *polkit_subject_new_for_gvariant (GVariant *variant, GError **error);
PolkitSubject  *polkit_subject_new_for_gvariant_invocation (GVariant              *variant,
                                                            GDBusMethodInvocation *invocation,
                                                            GError                **error);
PolkitIdentity *polkit_identity_new_for_gvariant (GVariant *variant, GError **error);

PolkitAuthorizationResult  *polkit_authorization_result_new_for_gvariant (GVariant *value);
GVariant *polkit_authorization_result_to_gvariant (PolkitAuthorizationResult *authorization_result);

PolkitTemporaryAuthorization *polkit_temporary_authorization_new    (const gchar                  *id,
                                                                     const gchar                  *action_id,
                                                                     PolkitSubject                *subject,
                                                                     guint64                       time_obtained,
                                                                     guint64                       time_expires);
PolkitTemporaryAuthorization *polkit_temporary_authorization_new_for_gvariant (GVariant *value,
                                                                               GError   **error);
GVariant *polkit_temporary_authorization_to_gvariant (PolkitTemporaryAuthorization *authorization);

GVariant *polkit_details_to_gvariant (PolkitDetails *details);
PolkitDetails *polkit_details_new_for_gvariant (GVariant *value);

PolkitActionDescription *
polkit_action_description_new (const gchar                 *action_id,
                               const gchar                 *description,
                               const gchar                 *message,
                               const gchar                 *vendor_name,
                               const gchar                 *vendor_url,
                               const gchar                 *icon_name,
                               PolkitImplicitAuthorization  implicit_any,
                               PolkitImplicitAuthorization  implicit_inactive,
                               PolkitImplicitAuthorization  implicit_active,
                               GHashTable                  *annotations);

#endif /* __POLKIT_PRIVATE_H */

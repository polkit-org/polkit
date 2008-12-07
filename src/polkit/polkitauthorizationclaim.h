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

#if !defined (_POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#include <glib-object.h>
#include <polkit/polkitsubject.h>

#ifndef __POLKIT_AUTHORIZATION_CLAIM_H__
#define __POLKIT_AUTHORIZATION_CLAIM_H__

G_BEGIN_DECLS

#define POLKIT_TYPE_AUTHORIZATION_CLAIM         (polkit_authorization_claim_get_type())
#define POLKIT_AUTHORIZATION_CLAIM(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), POLKIT_TYPE_AUTHORIZATION_CLAIM, PolkitAuthorizationClaim))
#define POLKIT_IS_AUTHORIZATION_CLAIM(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), POLKIT_TYPE_AUTHORIZATION_CLAIM))
#define POLKIT_AUTHORIZATION_CLAIM_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE((o), POLKIT_TYPE_AUTHORIZATION_CLAIM, PolkitAuthorizationClaimIface))

#if 0
typedef struct _PolkitAuthorizationClaim PolkitAuthorizationClaim; /* Dummy typedef */
#endif
typedef struct _PolkitAuthorizationClaimIface PolkitAuthorizationClaimIface;

struct _PolkitAuthorizationClaimIface
{
  GTypeInterface g_iface;
};

GType                       polkit_authorization_claim_get_type        (void) G_GNUC_CONST;
PolkitAuthorizationClaim   *polkit_authorization_claim_new             (PolkitSubject            *subject,
                                                                        const gchar              *action_id);

void                        polkit_authorization_claim_set_subject     (PolkitAuthorizationClaim *authorization_claim,
                                                                        PolkitSubject            *subject);
void                        polkit_authorization_claim_set_action_id   (PolkitAuthorizationClaim *authorization_claim,
                                                                        const gchar              *action_id);
void                        polkit_authorization_claim_set_attribute   (PolkitAuthorizationClaim *authorization_claim,
                                                                        const gchar              *key,
                                                                        const gchar              *value);

PolkitSubject              *polkit_authorization_claim_get_subject     (PolkitAuthorizationClaim *authorization_claim);
const gchar                *polkit_authorization_claim_get_action_id   (PolkitAuthorizationClaim *authorization_claim);
GHashTable                 *polkit_authorization_claim_get_attributes  (PolkitAuthorizationClaim *authorization_claim);


G_END_DECLS

#endif /* __POLKIT_AUTHORIZATION_CLAIM_H__ */

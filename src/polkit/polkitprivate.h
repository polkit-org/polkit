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

#include "polkitactiondescription.h"
#include "polkitsubject.h"
#include "polkitauthorizationclaim.h"
#include "_polkitbindings.h"

/* notes:
 *
 * - the _new_for_real() functions will ref the passed arg (you will still own the ref)
 * - the _get_real() functions will return a ref (you will own the ref)
 *
 */

PolkitActionDescription  *polkit_action_description_new_for_real (_PolkitActionDescription *real);
_PolkitActionDescription *polkit_action_description_get_real     (PolkitActionDescription  *action_description);

PolkitSubject  *polkit_subject_new_for_real (_PolkitSubject *real);
_PolkitSubject *polkit_subject_get_real     (PolkitSubject  *subject);

#if 0
PolkitAuthorizationClaim  *polkit_authorization_claim_new_for_real (_PolkitAuthorizationClaim *real);
_PolkitAuthorizationClaim *polkit_authorization_claim_get_real     (PolkitAuthorizationClaim  *claim);
#endif

#endif /* __POLKIT_PRIVATE_H */

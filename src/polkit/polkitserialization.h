/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

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

#ifndef __POLKIT_SERIALIZATION_H
#define __POLKIT_SERIALIZATION_H

#include <polkit/polkitauthorizationclaim.h>
#include <polkit/polkitauthorizationresult.h>

typedef GObject * (*PolkitSerializeToObjectFunc) (gpointer  data);
typedef void (*PolkitSerializeFromObjectFunc)    (GObject  *object,
                                                  GValue   *value);


PolkitAuthorizationResult _authorization_result_from_string   (const char                    *str);
char *                    _authorization_result_to_string     (PolkitAuthorizationResult      result);
PolkitSubject *           _subject_from_string                (const char                    *str);
char *                    _subject_to_string                  (PolkitSubject                 *subject);
void                      _authorization_claim_to_value       (PolkitAuthorizationClaim      *claim,
                                                               GValue                        *value);
PolkitAuthorizationClaim *_authorization_claim_from_data      (gpointer                       data);
GList *                   _serialize_ptr_array_to_obj_list    (GPtrArray                     *ptr_array,
                                                               PolkitSerializeToObjectFunc    func);
GPtrArray *               _serialize_ptr_array_from_obj_list  (GList                         *list,
                                                               PolkitSerializeFromObjectFunc  func);
void                      _free_serialized_obj_ptr_array      (GPtrArray                     *ptr_array);


#endif /* __POLKIT_SERIALIZATION_H */

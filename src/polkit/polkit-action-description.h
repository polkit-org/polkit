/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-policy-file-entry.h : entries in policy files
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/

#if !defined (POLKIT_COMPILATION) && !defined(_POLKIT_INSIDE_POLKIT_H)
#error "Only <polkit/polkit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef POLKIT_ACTION_DESCRIPTION_H
#define POLKIT_ACTION_DESCRIPTION_H

#include <polkit/polkit-types.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-implicit-authorization.h>
#include <polkit/polkit-error.h>

POLKIT_BEGIN_DECLS

struct _PolKitActionDescription;
typedef struct _PolKitActionDescription PolKitActionDescription;

/**
 * PolKitActionDescriptionAnnotationsForeachFunc:
 * @action_description: the policy file entry
 * @key: key of the annotation
 * @value: corrosponding value of the annotation
 * @user_data: user data passed to polkit_action_description_annotations_foreach()
 *
 * Callback function for polkit_action_description_annotations_foreach().
 *
 * Returns: Pass #TRUE to short-circuit, e.g. stop the iteration
 **/
typedef polkit_bool_t (*PolKitActionDescriptionAnnotationsForeachFunc) (PolKitActionDescription *action_description,
                                                                      const char *key,
                                                                      const char *value,
                                                                      void *user_data);

PolKitActionDescription *polkit_action_description_ref   (PolKitActionDescription *action_description);
void                   polkit_action_description_unref (PolKitActionDescription *action_description);
void                   polkit_action_description_debug (PolKitActionDescription *action_description);

const char                  *polkit_action_description_get_id       (PolKitActionDescription *action_description);
PolKitImplicitAuthorization *polkit_action_description_get_implicit_authorization  (PolKitActionDescription *action_description);

const char            *polkit_action_description_get_action_description (PolKitActionDescription *action_description);
const char            *polkit_action_description_get_action_message (PolKitActionDescription *action_description);

const char            *polkit_action_description_get_action_vendor     (PolKitActionDescription *action_description);
const char            *polkit_action_description_get_action_vendor_url (PolKitActionDescription *action_description);
const char            *polkit_action_description_get_action_icon_name  (PolKitActionDescription *action_description);

polkit_bool_t          polkit_action_description_annotations_foreach (PolKitActionDescription *action_description,
                                                                     PolKitActionDescriptionAnnotationsForeachFunc cb,
                                                                     void *user_data);
const char            *polkit_action_description_get_annotation (PolKitActionDescription *action_description,
                                                                const char *key);

PolKitImplicitAuthorization *polkit_action_description_get_implicit_authorization_factory (PolKitActionDescription  *action_description);
polkit_bool_t          polkit_action_description_set_implicit_authorization         (PolKitActionDescription  *action_description,
                                                                     PolKitImplicitAuthorization *implicit_authorzation,
                                                                     PolKitError           **error);

POLKIT_END_DECLS

#endif /* POLKIT_ACTION_DESCRIPTION_H */



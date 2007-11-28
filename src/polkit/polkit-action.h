/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-action.h : actions
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

#ifndef POLKIT_ACTION_H
#define POLKIT_ACTION_H

#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

struct _PolKitAction;
typedef struct _PolKitAction PolKitAction;

PolKitAction *polkit_action_new           (void);
PolKitAction *polkit_action_ref           (PolKitAction *action);
void          polkit_action_unref         (PolKitAction *action);
polkit_bool_t polkit_action_set_action_id (PolKitAction *action, const char  *action_id);
polkit_bool_t polkit_action_get_action_id (PolKitAction *action, char       **out_action_id);

void          polkit_action_debug         (PolKitAction *action);
polkit_bool_t polkit_action_validate      (PolKitAction *action);

polkit_bool_t polkit_action_validate_id   (const char   *action_id);

POLKIT_END_DECLS

#endif /* POLKIT_ACTION_H */



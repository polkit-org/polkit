/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit.h : library for querying system-wide policy
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

#ifndef POLKIT_H
#define POLKIT_H

#define _POLKIT_INSIDE_POLKIT_H 1
#include <polkit/polkit-types.h>
#include <polkit/polkit-sysdeps.h>
#include <polkit/polkit-error.h>
#include <polkit/polkit-result.h>
#include <polkit/polkit-context.h>
#include <polkit/polkit-action.h>
#include <polkit/polkit-seat.h>
#include <polkit/polkit-session.h>
#include <polkit/polkit-caller.h>
#include <polkit/polkit-action-description.h>
#include <polkit/polkit-implicit-authorization.h>
#include <polkit/polkit-authorization.h>
#include <polkit/polkit-authorization-db.h>
#include <polkit/polkit-tracker.h>
#include <polkit/polkit-simple.h>
#undef _POLKIT_INSIDE_POLKIT_H

#endif /* POLKIT_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-test.h : PolicyKit test
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

#if !defined (POLKIT_COMPILATION)
#error "polkit-test.h is a private file"
#endif

#ifndef POLKIT_TEST_H
#define POLKIT_TEST_H

#include <kit/kit.h>
#include <polkit/polkit-types.h>

POLKIT_BEGIN_DECLS

extern KitTest _test_action;
extern KitTest _test_error;
extern KitTest _test_result;
extern KitTest _test_seat;
extern KitTest _test_session;
extern KitTest _test_caller;
extern KitTest _test_policy_default;
extern KitTest _test_policy_file_entry;
extern KitTest _test_policy_file;
extern KitTest _test_policy_cache;
extern KitTest _test_authorization_constraint;
extern KitTest _test_authorization;
extern KitTest _test_authorization_db;
extern KitTest _test_sysdeps;
extern KitTest _test_utils;
extern KitTest _test_context;

POLKIT_END_DECLS

#endif /* POLKIT_TEST_H */



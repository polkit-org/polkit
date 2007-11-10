/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-test.h : PolicyKit test
 *
 * Copyright (C) 2007 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#if !defined (KIT_COMPILATION)
#error "kit-test.h is a private file."
#endif

#ifndef KIT_TEST_H
#define KIT_TEST_H

#include <kit/kit.h>

KIT_BEGIN_DECLS

/**
 * KitTest:
 *
 * Test suite abstraction.
 */
typedef struct {
        /*< private >*/
        const char *name;
        void (*setup) (void);
        void (*teardown) (void);
        kit_bool_t (*run) (void);
} KitTest;

extern KitTest _test_memory;
extern KitTest _test_string;
extern KitTest _test_hash;
extern KitTest _test_list;
extern KitTest _test_file;
extern KitTest _test_message;

KIT_END_DECLS

#endif /* KIT_TEST_H */



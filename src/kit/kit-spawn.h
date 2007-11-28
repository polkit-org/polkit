/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-spawn.h : Spawn utilities
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

#if !defined (KIT_COMPILATION) && !defined(_KIT_INSIDE_KIT_H)
#error "Only <kit/kit.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef KIT_SPAWN_H
#define KIT_SPAWN_H

#include <kit/kit.h>

KIT_BEGIN_DECLS

/**
 * KitSpawnFlags:
 * @KIT_SPAWN_CHILD_INHERITS_STDIN: If not set, child's stdin will be attached to <literal>/dev/null</literal>
 * @KIT_SPAWN_STDOUT_TO_DEV_NULL: If set childs output will be sent to <literal>/dev/null</literal>
 * @KIT_SPAWN_STDERR_TO_DEV_NULL: If set childs error output will be sent to <literal>/dev/null</literal>
 *
 * Flags passed to kit_spawn_sync().
 */
typedef enum {
        KIT_SPAWN_CHILD_INHERITS_STDIN = 1 << 0,
        KIT_SPAWN_STDOUT_TO_DEV_NULL   = 1 << 1,
        KIT_SPAWN_STDERR_TO_DEV_NULL   = 1 << 2,
} KitSpawnFlags;


kit_bool_t kit_spawn_sync (const char     *working_directory,
                           KitSpawnFlags   flags,
                           char          **argv,
                           char          **envp,
                           char           *stdin,
                           char          **stdout,
                           char          **stderr,
                           int            *out_exit_status);

KIT_END_DECLS

#endif /* KIT_SPAWN_H */



/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * polkit-sysdeps.c : Various platform specific utility functions
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>
#include <syslog.h>

#include "polkit-sysdeps.h"
#include "polkit-private.h"
#include "polkit-test.h"

/**
 * SECTION:polkit-sysdeps
 * @title: System Dependencies
 * @short_description: Various platform specific utility functions
 *
 * Various platform specific utility functions.
 *
 * Since: 0.7
 **/


/**
 * polkit_sysdeps_get_start_time_for_pid:
 * @pid: process id
 *
 * Get when a process started.
 *
 * Returns: start time for the process or 0 if an error occured and errno will be set
 *
 * Since: 0.7
 */
polkit_uint64_t 
polkit_sysdeps_get_start_time_for_pid (pid_t pid)
{
        char *filename;
        char *contents;
        size_t length;
        polkit_uint64_t start_time;
        char **tokens;
        size_t num_tokens;
        char *p;
        char *endp;

        start_time = 0;
        contents = NULL;

        filename = kit_strdup_printf ("/proc/%d/stat", pid);
        if (filename == NULL) {
                errno = ENOMEM;
                goto out;
        }

        if (!kit_file_get_contents (filename, &contents, &length)) {
                //fprintf (stderr, "Cannot get contents of '%s': %s\n", filename, error->message);
                goto out;
        }

        /* start time is the 19th token after the '(process name)' entry */

        p = strchr (contents, ')');
        if (p == NULL) {
                goto out;
        }
        p += 2; /* skip ') ' */
        if (p - contents >= (int) length) {
                goto out;
        }

        tokens = kit_strsplit (p, ' ', &num_tokens);
        if (tokens == NULL)
                goto out;

        if (num_tokens < 20) {
                goto out;
        }

        start_time = strtoll (tokens[19], &endp, 10);
        if (endp == tokens[19]) {
                goto out;
        }

        kit_strfreev (tokens);

out:
        kit_free (filename);
        kit_free (contents);
        return start_time;
}

/**
 * polkit_sysdeps_get_exe_for_pid:
 * @pid: process id
 * @out_buf: buffer to store the string representation in
 * @buf_size: size of buffer
 *
 * Get the name of the binary a given process was started from. Note
 * that this is not reliable information; it should not be part of any
 * security decision. If the information could not be obtained 0 is
 * returned and out_buf will be set to "(unknown)".
 *
 * Returns: Number of characters written (not including trailing
 * '\0'). If the output was truncated due to the buffer being too
 * small, buf_size will be returned. Thus, a return value of buf_size
 * or more indicates that the output was truncated (see snprintf(3))
 * or an error occured. If the name cannot be found, -1 will be
 * returned.
 *
 * Since: 0.7
 */
int
polkit_sysdeps_get_exe_for_pid (pid_t pid, char *out_buf, size_t buf_size)
{
        int ret;
        char proc_name[32];

        ret = 0;

        snprintf (proc_name, sizeof (proc_name), "/proc/%d/exe", pid);
        ret = readlink (proc_name, out_buf, buf_size - 1);
        if (ret == -1) {
                strncpy (out_buf, "(unknown)", buf_size);
                goto out;
        }
        kit_assert (ret >= 0 && ret < (int) buf_size - 1);
        out_buf[ret] = '\0';

out:
        return ret;
}

#ifdef POLKIT_BUILD_TESTS

static polkit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_sysdeps = {
        "polkit_sysdeps",
        NULL,
        NULL,
        _run_test
};

#endif /* POLKIT_BUILD_TESTS */

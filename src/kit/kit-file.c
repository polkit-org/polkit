/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-file.c : File utilities
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <kit/kit.h>
#include "kit-test.h"


/**
 * SECTION:kit-file
 * @title: File utilities
 * @short_description: File utilities
 *
 * Various file utilities.
 **/

#define BUF_SIZE 4096

/**
 * kit_file_get_contents:
 * @path: path to file
 * @out_contents: Return location for allocated memory. Free with kit_free().
 * @out_contents_size: Return location for size of the file.
 * 
 * Reads an entire file into allocated memory.
 *
 * Returns: #TRUE if the file was read into memory; #FALSE if an error
 * occured and errno will be set. On OOM, errno will be set to
 * ENOMEM. If the file doesn't exist, errno will be set to ENOENT.
 */
kit_bool_t
kit_file_get_contents (const char *path, char **out_contents, size_t *out_contents_size)
{
        int fd;
        kit_bool_t ret;
        ssize_t num_read;
        char *p;
        char *q;
        size_t total_allocated;
        size_t total_size;
        char buf[BUF_SIZE];

        kit_return_val_if_fail (path != NULL, FALSE);
        kit_return_val_if_fail (out_contents != NULL, FALSE);
        kit_return_val_if_fail (out_contents_size != NULL, FALSE);

        fd = -1;
        ret = FALSE;
        *out_contents = NULL;
        p = NULL;

        fd = open (path, O_RDONLY);
        if (fd == -1)
                goto out;

        p = kit_malloc (BUF_SIZE);
        if (p == NULL) {
                errno = ENOMEM;
                goto out;
        }
        total_allocated = BUF_SIZE;
        total_size = 0;

        do {
        again:
                num_read = read (fd, buf, BUF_SIZE);
                if (num_read == -1) {
                        if (errno == EINTR)
                                goto again;
                        else
                                goto out;
                }


                if (total_size + num_read > total_allocated) {
                        total_allocated += BUF_SIZE;
                        q = kit_realloc (p, total_allocated);
                        if (q == NULL) {
                                errno = ENOMEM;
                                goto out;
                        }
                        p = q;
                }

                memcpy (p + total_size, buf, num_read);
                total_size += num_read;
                
        } while (num_read > 0);

        /* add terminating zero */
        if (total_size + 1 > total_allocated) {
                total_allocated += BUF_SIZE;
                q = kit_realloc (p, total_allocated);
                if (q == NULL) {
                        errno = ENOMEM;
                        goto out;
                }
                p = q;
        }
        p[total_size] = '\0';

        *out_contents = p;
        *out_contents_size = total_size;
        ret = TRUE;

out:
        if (fd >= 0) {
        again2:
                if (close (fd) != 0) {
                        if (errno == EINTR)
                                goto again2;
                        else
                                ret = FALSE;
                }
        }

        if (!ret) {
                kit_free (p);
                *out_contents = NULL;
        }

        return ret;
}

static kit_bool_t
_write_to_fd (int fd, const char *str, ssize_t str_len)
{
        kit_bool_t ret;
        ssize_t written;

        ret = FALSE;

        written = 0;
        while (written < str_len) {
                ssize_t ret;
                ret = write (fd, str + written, str_len - written);
                if (ret < 0) {
                        if (errno == EAGAIN || errno == EINTR) {
                                continue;
                        } else {
                                goto out;
                        }
                }
                written += ret;
        }

        ret = TRUE;

out:
        return ret;
}

/**
 * kit_file_set_contents:
 * @path: path to file
 * @mode: mode for file
 * @contents: contents to set
 * @contents_size: size of contents
 *
 * Writes all of contents to a file named @path, with good error
 * checking. If a file called @path already exists it will be
 * overwritten. This write is atomic in the sense that it is first
 * written to a temporary file which is then renamed to the final
 * name.
 *
 * If the file already exists hard links to @path will break. Also
 * since the file is recreated, existing permissions, access control
 * lists, metadata etc. may be lost. If @path is a symbolic link, the
 * link itself will be replaced, not the linked file.
 *
 * Returns: #TRUE if contents were set; #FALSE if an error occured and
 * errno will be set
 */
kit_bool_t
kit_file_set_contents (const char *path, mode_t mode, const char *contents, size_t contents_size)
{
        int fd;
        char *path_tmp;
        kit_bool_t ret;

        path_tmp = NULL;
        ret = FALSE;

        kit_return_val_if_fail ((contents == NULL && contents_size == 0) || (contents != NULL), FALSE);
        kit_return_val_if_fail (path != NULL, FALSE);

        path_tmp = kit_strdup_printf ("%s.XXXXXX", path);
        if (path_tmp == NULL) {
                errno = ENOMEM;
                goto out;
        }

        fd = mkstemp (path_tmp);
        if (fd < 0) {
                kit_warning ("Cannot create file '%s': %m", path_tmp);
                goto out;
        }
        if (fchmod (fd, mode) != 0) {
                kit_warning ("Cannot change mode for '%s' to 0%o: %m", path_tmp, mode);
                close (fd);
                unlink (path_tmp);
                goto out;
        }

        if (contents_size > 0) {
                if (!_write_to_fd (fd, contents, contents_size)) {
                        kit_warning ("Cannot write to file %s: %m", path_tmp);
                        close (fd);
                        if (unlink (path_tmp) != 0) {
                                kit_warning ("Cannot unlink %s: %m", path_tmp);
                        }
                        goto out;
                }
        }
        close (fd);

        if (rename (path_tmp, path) != 0) {
                kit_warning ("Cannot rename %s to %s: %m", path_tmp, path);
                if (unlink (path_tmp) != 0) {
                        kit_warning ("Cannot unlink %s: %m", path_tmp);
                }
                goto out;
        }

        ret = TRUE;

out:
        if (path_tmp != NULL)
                kit_free (path_tmp);

        return ret;
}

/**
 * _kit_get_num_fd:
 *
 * Determines the number of open file descriptors
 *
 * Returns: Number of open file descriptors
 */
size_t 
_kit_get_num_fd (void)
{
        DIR *dir;
        char buf[128];
        ssize_t num;
#ifdef HAVE_READDIR64
        struct dirent64 *d;
#else
	struct dirent *d;
#endif

        num = -1;

        snprintf (buf, sizeof (buf), "/proc/%d/fd", getpid ());

        dir = opendir (buf);
        if (dir == NULL) {
                kit_warning ("error calling opendir on %s: %m\n", buf);
                goto out;
        }

        num = -2;
#ifdef HAVE_READDIR64
        while ((d = readdir64 (dir)) != NULL) {
#else
	while ((d = readdir (dir)) != NULL) {
#endif
                if (d->d_name == NULL)
                        continue;
                num++;
        }

out:
        if (dir != NULL)
                closedir (dir);
        return num;
}


#ifdef KIT_BUILD_TESTS

static kit_bool_t
_run_test (void)
{
        char path[] = "/tmp/kit-test";
        char *buf;
        size_t buf_size;
        char *p;
        size_t s;
        unsigned int n;

        buf_size = 3 * BUF_SIZE;
        if ((buf = kit_malloc (buf_size)) == NULL)
                goto out;

        for (n = 0; n < buf_size; n++)
                buf[n] = n;

        if (!kit_file_set_contents (path, 0400, buf, buf_size)) {
                kit_assert (errno == ENOMEM);
        } else {
                if (!kit_file_get_contents (path, &p, &s)) {
                        kit_assert (errno == ENOMEM);
                } else {
                        kit_assert (s == buf_size && memcmp (p, buf, buf_size) == 0);
                        kit_free (p);
                }

                kit_assert (unlink (path) == 0);

                kit_assert (!kit_file_get_contents (path, &p, &s));
        }

        kit_free (buf);

out:
        return TRUE;
}

KitTest _test_file = {
        "kit_file",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/***************************************************************************
 *
 * kit-entity.c : Entity management
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef BUILT_R_DYNAMIC
#include <execinfo.h>
#endif

#include <kit/kit-entity.h>
#include <kit/kit-test.h>

/**
 * SECTION:kit-entity
 * @title: Entity management
 * @short_description: Entity management
 *
 * Functions used for entity management.
 **/

#ifdef KIT_BUILD_TESTS

/**
 * kit_getpwnam:
 * @username: user name to look up
 *
 * Like getpwnam(3) from the standard C library but tweaked for unit
 * testing. TODO: explain how.
 *
 * Returns: See getpwnam(3)
 */
struct passwd *
kit_getpwnam (const char *username)
{
        struct passwd *pw;
        FILE *f;
        const char *passwd_file;

        f = NULL;
        pw = NULL;

        if ((passwd_file = getenv ("KIT_TEST_PASSWD_FILE")) == NULL)
                return getpwnam (username);

        f = fopen (passwd_file, "r");
        if (f == NULL)
                goto out;

        while ((pw = fgetpwent (f)) != NULL) {
                if (strcmp (pw->pw_name, username) == 0)
                        goto out;
        }

out:
        if (f != NULL)
                fclose (f);
        return pw;
}

/**
 * kit_getpwuid:
 * @username: user name to look up
 *
 * Like getpwuid(3) from the standard C library but tweaked for unit
 * testing. TODO: explain how.
 *
 * Returns: See getpwuid(3)
 */
struct passwd *
kit_getpwuid (uid_t uid)
{
        struct passwd *pw;
        FILE *f;
        const char *passwd_file;

        f = NULL;
        pw = NULL;

        if ((passwd_file = getenv ("KIT_TEST_PASSWD_FILE")) == NULL)
                return getpwuid (uid);

        f = fopen (passwd_file, "r");
        if (f == NULL)
                goto out;

        while ((pw = fgetpwent (f)) != NULL) {
                if (pw->pw_uid == uid)
                        goto out;
        }

out:
        if (f != NULL)
                fclose (f);
        return pw;
}

#else

struct passwd *
kit_getpwnam (const char *username)
{
        return getpwnam (username);
}

struct passwd *
kit_getpwuid (uid_t uid)
{
        return getpwuid (uid);
}
#endif


#ifdef KIT_BUILD_TESTS

static kit_bool_t
_run_test (void)
{
        return TRUE;
}

KitTest _test_entity = {
        "kit_entity",
        NULL,
        NULL,
        _run_test
};

#endif /* KIT_BUILD_TESTS */

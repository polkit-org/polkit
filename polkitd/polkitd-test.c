/***************************************************************************
 * CVSID: $Id$
 *
 * polkitd-test.c : Test harness for PolicyKit daemon
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib/gstdio.h>

#include "policy.h"

static char *testdir;

static void 
my_exit (int exit_code)
{
	int rc;
	GDir *dir;
	GError *err;
	const char *f;

	g_print ("Removing tmpdir '%s'\n", testdir);
	
	err = NULL;
	if ((dir = g_dir_open (testdir, 0, &err)) == NULL) {
		g_warning ("Unable to open %s: %s", testdir, err->message);
		g_error_free (err);
		goto error;
	}
	while ((f = g_dir_read_name (dir)) != NULL) {
		char *file;

		file = g_strdup_printf ("%s/%s", testdir, f);
		rc = g_unlink (file);
		if (rc != 0) {
			g_warning ("Unable to unlink %s: %d (%s)", file, errno, strerror (errno));
			goto error;
		}
		g_free (file);
	}

	g_dir_close (dir);
	
	rc = g_rmdir (testdir);
	if (rc != 0) {
		g_warning ("Unable to rmdir %s: %d (%s)", testdir, errno, strerror (errno));
		goto error;
	}

error:	
	exit (exit_code);
}

static void 
do_check (const char *policy,
	  uid_t uid,
	  int num_gids,
	  gid_t *gids,
	  const char *resource,
	  gboolean expected)
{
	int i;
	gboolean allowed;
	gboolean is_temporary;
	char *gidstring;
	char **out_is_privileged_but_restricted; 
	GString *str;

	str = g_string_new ("");
	for (i = 0; i < num_gids; i++) {
		if (i != 0)
			g_string_append (str, ", ");
		g_string_append_printf (str, "%d", gids[i]);
	}
	gidstring = g_string_free (str, FALSE);

	if (POLICY_RESULT_OK != policy_is_uid_gid_allowed_for_policy ( uid, 
								       num_gids, 
								       gids, 
								       policy, 
								       resource, 
								       &allowed, 
								       &is_temporary, 
							  	       out_is_privileged_but_restricted,
								       NULL, NULL)) {
		g_warning ("fail: no policy %s", policy);
		my_exit (1);
	}
	
	if (allowed != expected) {
		g_warning ("fail: for uid %d (gids %s) expected %s on privilege '%s' for resource '%s' but got %s", 
			   uid, gidstring, 
			   expected ? "TRUE" : "FALSE", 
			   policy, 
			   (char*) (resource != NULL ? resource : ""), 
			   allowed ? "TRUE" : "FALSE");
		my_exit (1);
	}
	
	g_print ("pass: uid %d (gids %s) got %s on privilege '%s' for resource '%s'\n", 
		 uid, gidstring, 
		 expected ? "TRUE " : "FALSE", 
		 policy, 
		 (char*) (resource != NULL ? resource : ""));

	g_free (gidstring);
}

static void
write_test_policy (const char *policy, const char *allow_rule, const char *deny_rule)
{
	char *file;
	FILE *f;

	file = g_strdup_printf ("%s/%s.privilege", testdir, policy);
	f = fopen (file, "w");
	if (f == NULL) {
		g_warning ("Cannot created test policy '%s'", file);
		my_exit (1);
	}
	fprintf (f, 
		 "[Privilege]\n"
		 "SufficientPrivileges=\n"
		 "RequiredPrivileges=\n"
		 "Allow=%s\n"
		 "Deny=%s\n", 
		 allow_rule, deny_rule);
	fclose (f);

	g_print ("Created test policy '%s' at '%s'\n"
		 "  Allow '%s'\n"
		 "  Deny  '%s'\n",
		 policy, file, allow_rule, deny_rule);

	g_free (file);
}

static void
do_read_tests (void)
{
	gid_t gid500[1] = {500};
	int gid500_len = sizeof (gid500) / sizeof (gid_t);
	gid_t gid501[1] = {501};
	int gid501_len = sizeof (gid501) / sizeof (gid_t);
	gid_t gid502[1] = {502};
	int gid502_len = sizeof (gid502) / sizeof (gid_t);

	gid_t gid500_1[2] = {500, 1};
	int gid500_1_len = sizeof (gid500_1) / sizeof (gid_t);
	gid_t gid501_1[2] = {501, 1};
	int gid501_1_len = sizeof (gid501_1) / sizeof (gid_t);
	gid_t gid502_1[2] = {502, 1};
	int gid502_1_len = sizeof (gid502_1) / sizeof (gid_t);

	/* feel free to add more tests here */

	write_test_policy ("test0", "uid:__none__ uid:500", "");
	do_check ("test0", 500, gid500_len, gid500, NULL, TRUE);
	do_check ("test0", 501, gid501_len, gid501, NULL, FALSE);
	do_check ("test0", 502, gid502_len, gid502, NULL, FALSE);

	write_test_policy ("test1", "uid:__all__", "uid:500:res0");
	do_check ("test1", 500, gid500_len, gid500, NULL, TRUE);
	do_check ("test1", 501, gid501_len, gid501, NULL, TRUE);
	do_check ("test1", 502, gid502_len, gid502, NULL, TRUE);
	do_check ("test1", 500, gid500_len, gid500, "res0", FALSE);
	do_check ("test1", 501, gid501_len, gid501, "res0", TRUE);
	do_check ("test1", 502, gid502_len, gid502, "res0", TRUE);
	do_check ("test1", 500, gid500_len, gid500, "res1", TRUE);
	do_check ("test1", 501, gid501_len, gid501, "res1", TRUE);
	do_check ("test1", 502, gid502_len, gid502, "res1", TRUE);
	
	write_test_policy ("test2", "gid:1", "uid:501");	
	do_check ("test2", 500, gid500_len, gid500, NULL, FALSE);
	do_check ("test2", 501, gid501_len, gid501, NULL, FALSE);
	do_check ("test2", 502, gid502_len, gid502, NULL, FALSE);
	do_check ("test2", 500, gid500_1_len, gid500_1, NULL, TRUE);
	do_check ("test2", 501, gid501_1_len, gid501_1, NULL, FALSE);
	do_check ("test2", 502, gid502_1_len, gid502_1, NULL, TRUE);
	
	write_test_policy ("test3", "gid:1 uid:502:res1", "uid:501 uid:500:res0");	
	do_check ("test3", 500, gid500_1_len, gid500_1, "res0", FALSE);
	do_check ("test3", 501, gid501_1_len, gid501_1, "res0", FALSE);
	do_check ("test3", 502, gid502_1_len, gid502_1, "res0", TRUE);
	do_check ("test3", 500, gid500_1_len, gid500_1, "res1", TRUE);
	do_check ("test3", 501, gid501_1_len, gid501_1, "res1", FALSE);
	do_check ("test3", 502, gid502_1_len, gid502_1, "res1", TRUE);
	do_check ("test3", 500, gid500_len, gid500, "res1", FALSE);
	do_check ("test3", 501, gid501_len, gid501, "res1", FALSE);
	do_check ("test3", 502, gid502_len, gid502, "res1", TRUE);

	write_test_policy ("test4", "gid:1:res1 uid:500:res2", "gid:502:res2");	
	do_check ("test4", 500, gid500_1_len, gid500_1, "res0", FALSE);
	do_check ("test4", 501, gid501_1_len, gid501_1, "res0", FALSE);
	do_check ("test4", 502, gid502_1_len, gid502_1, "res0", FALSE);
	do_check ("test4", 500, gid500_1_len, gid500_1, "res1", TRUE);
	do_check ("test4", 501, gid501_1_len, gid501_1, "res1", TRUE);
	do_check ("test4", 502, gid502_1_len, gid502_1, "res1", TRUE);
	do_check ("test4", 500, gid500_len, gid500, "res2", TRUE);
	do_check ("test4", 501, gid501_len, gid501, "res2", FALSE);
	do_check ("test4", 502, gid502_len, gid502, "res2", FALSE);

	write_test_policy ("test5", "gid:1", "uid:500:res-has-:colon-in-name");	
	do_check ("test5", 500, gid500_1_len, gid500_1, "res-has-:colon-in-name", FALSE);
	do_check ("test5", 501, gid501_1_len, gid501_1, "res-has-:colon-in-name", TRUE);
	do_check ("test5", 502, gid502_1_len, gid502_1, "res-has-:colon-in-name", TRUE);
	do_check ("test5", 500, gid500_len, gid500, "res-has-:colon-in-name", FALSE);
	do_check ("test5", 501, gid501_len, gid501, "res-has-:colon-in-name", FALSE);
	do_check ("test5", 502, gid502_len, gid502, "res-has-:colon-in-name", FALSE);

}

int 
main (int argc, char *argv[])
{
	int i;
	GList *l;
	GList *policies;

	testdir = g_strdup ("/tmp/policy-test-XXXXXX");
	testdir = mkdtemp (testdir);
	if (testdir == NULL) {
		g_warning ("Cannot create tmpdir, errno %d (%s)", errno, strerror (errno));
		g_free (testdir);
		exit (1);
	}

	g_message ("policy-test started; using tmpdir=%s", testdir);

	policy_util_set_policy_directory (testdir);

	do_read_tests ();

	if (policy_get_policies (&policies) != POLICY_RESULT_OK) {
		g_message ("Cannot get policies");
		goto fail;
	}
	g_print ("Loaded %d policies\n", g_list_length (policies));
	for (l = policies, i = 0; l != NULL; l = g_list_next (l), i++) {
		const char *policy;
		policy = (const char *) l->data;
		g_print (" policy %d: '%s'\n", i, policy);
	}
	g_list_foreach (policies, (GFunc) g_free, NULL);
	g_list_free (policies);

	g_print ("policy-test completed\n");

	my_exit (0);

fail:
	my_exit (1);
	return 1;
}

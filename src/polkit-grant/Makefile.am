## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	-DPOLKIT_COMPILATION \
	@GLIB_CFLAGS@ @DBUS_CFLAGS@

lib_LTLIBRARIES=libpolkit-grant.la

libpolkit_grantincludedir=$(includedir)/PolicyKit/polkit-grant

libpolkit_grantinclude_HEADERS =              				\
	polkit-grant.h

libpolkit_grant_la_SOURCES =      					\
	polkit-grant.h		polkit-grant.c


if POLKIT_AUTHDB_DUMMY
libpolkit_grant_la_SOURCES += polkit-authorization-db-dummy-write.c
endif

if POLKIT_AUTHDB_DEFAULT
libpolkit_grant_la_SOURCES += polkit-authorization-db-write.c
endif

libpolkit_grant_la_LIBADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/src/polkit/libpolkit.la

libpolkit_grant_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) @R_DYNAMIC_LDFLAG@

# Only if the authdb backend has the capability POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN
# then the backend must supply the /usr/libexec/polkit-grant-helper program.. also remember to
# adjust the PAM stuff in data/Makefile.am
#
if POLKIT_AUTHDB_DEFAULT
libexec_PROGRAMS = polkit-grant-helper

if POLKIT_AUTHFW_PAM
libexec_PROGRAMS += polkit-grant-helper-pam
endif

libexec_PROGRAMS += polkit-explicit-grant-helper polkit-revoke-helper 

polkit_grant_helper_SOURCES = polkit-grant-helper.c
polkit_grant_helper_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/src/polkit/libpolkit.la $(top_builddir)/src/polkit-dbus/libpolkit-dbus.la libpolkit-grant.la

if POLKIT_AUTHFW_PAM
polkit_grant_helper_pam_SOURCES = polkit-grant-helper-pam.c
polkit_grant_helper_pam_LDADD = @AUTH_LIBS@
endif

polkit_explicit_grant_helper_SOURCES = polkit-explicit-grant-helper.c
polkit_explicit_grant_helper_CFLAGS = @DBUS_CFLAGS@
polkit_explicit_grant_helper_LDADD = $(top_builddir)/src/polkit/libpolkit.la $(top_builddir)/src/polkit-dbus/libpolkit-dbus.la libpolkit-grant.la

polkit_revoke_helper_SOURCES = polkit-revoke-helper.c
polkit_revoke_helper_CFLAGS = @DBUS_CFLAGS@
polkit_revoke_helper_LDADD = $(top_builddir)/src/polkit/libpolkit.la $(top_builddir)/src/polkit-dbus/libpolkit-dbus.la

# polkit-grant-helper needs to be setgid polkituser to be able to
# write cookies to /var/lib/PolicyKit and /var/run/PolicyKit
#
# polkit-grant-helper-* need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users. As only polkit-grant-helper will invoke it we
# make it owned by the polkitiuser group and non-executable to the
# world
#
# polkit-explicit-grant-helper needs to be setgid $POLKIT_GROUP to be
# able to edit authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
# polkit-revoke-helper needs to be setgid $POLKIT_GROUP to be able to
# edit authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
install-exec-hook:
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-grant-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-grant-helper
if POLKIT_AUTHFW_PAM
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-grant-helper-pam
	-chmod 4754 $(DESTDIR)$(libexecdir)/polkit-grant-helper-pam
endif
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-explicit-grant-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-explicit-grant-helper
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-revoke-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-revoke-helper
endif

## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if KIT_BUILD_TESTS
TESTS_ENVIRONMENT=
TESTS=polkit-grant-test

check_PROGRAMS=$(TESTS)

polkit_grant_test_SOURCES=				\
	polkit-grant-test.h	polkit-grant-test.c

polkit_grant_test_LDADD=$(top_builddir)/src/polkit-grant/libpolkit-grant.la
polkit_grant_test_LDFLAGS=

if KIT_GCOV_ENABLED
clean-gcov:
	rm -f *.gcov .libs/*.gcda

.PHONY: coverage-report.txt covered-files.txt

covered-files.txt :
	echo $(addprefix src/polkit-grant/,$(filter %.c,$(libpolkit_grant_la_SOURCES))) > covered-files.txt
if POLKIT_AUTHDB_DEFAULT
	echo src/polkit-grant/polkit-explicit-grant-helper.c >> covered-files.txt
	echo src/polkit-grant/polkit-grant-helper.c >> covered-files.txt
if POLKIT_AUTHFW_PAM
	echo src/polkit-grant/polkit-grant-helper-pam.c >> covered-files.txt
endif
	echo src/polkit-grant/polkit-revoke-helper.c >> covered-files.txt
endif

coverage-report.txt : covered-files.txt clean-gcov all check 
	gcov $(filter %.c,$(libpolkit_grant_la_SOURCES)) -o .libs/ > /dev/null
if POLKIT_AUTHDB_DEFAULT
	gcov polkit-explicit-grant-helper.c -o .libs/ > /dev/null
	gcov polkit-grant-helper.c -o .libs/ > /dev/null
if POLKIT_AUTHFW_PAM
	gcov polkit-grant-helper-pam.c -o .libs/ > /dev/null
endif
	gcov polkit-revoke-helper.c -o .libs/ > /dev/null
endif
	$(top_srcdir)/test/create-coverage-report.sh "module polkit-grant" `cat covered-files.txt` > coverage-report.txt

check-coverage : coverage-report.txt
	cat coverage-report.txt
else
coverage-report.txt:
	@echo "Need to reconfigure with --enable-gcov"

check-coverage:
	@echo "Need to reconfigure with --enable-gcov"
endif

else
TESTS=
endif

clean-local :
	rm -f *~ *.bb *.bbg *.da *.gcov .libs/*.da .libs/*.bbg 

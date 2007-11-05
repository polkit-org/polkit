## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	-DPOLKIT_COMPILATION \
	@GLIB_CFLAGS@

lib_LTLIBRARIES=libpolkit.la

libpolkitincludedir=$(includedir)/PolicyKit/polkit

libpolkitinclude_HEADERS =              		\
	polkit.h					\
	polkit-sysdeps.h				\
	polkit-memory.h					\
	polkit-hash.h					\
	polkit-types.h					\
	polkit-error.h					\
	polkit-result.h					\
	polkit-context.h				\
	polkit-action.h					\
	polkit-seat.h					\
	polkit-session.h				\
	polkit-caller.h					\
	polkit-policy-file-entry.h			\
	polkit-policy-file.h				\
	polkit-policy-cache.h				\
	polkit-policy-default.h				\
	polkit-config.h					\
	polkit-authorization.h				\
	polkit-authorization-constraint.h		\
	polkit-authorization-db.h

libpolkit_la_SOURCES =                                					\
	polkit.h									\
	polkit-private.h								\
	polkit-types.h									\
	polkit-memory.h				polkit-memory.c				\
	polkit-hash.h				polkit-hash.c				\
	polkit-sysdeps.h			polkit-sysdeps.c			\
	polkit-error.h				polkit-error.c				\
	polkit-result.h				polkit-result.c				\
	polkit-context.h			polkit-context.c			\
	polkit-action.h				polkit-action.c				\
	polkit-seat.h				polkit-seat.c				\
	polkit-session.h			polkit-session.c			\
	polkit-caller.h				polkit-caller.c				\
	polkit-policy-file-entry.h		polkit-policy-file-entry.c		\
	polkit-policy-file.h			polkit-policy-file.c			\
	polkit-policy-cache.h			polkit-policy-cache.c			\
	polkit-policy-default.h			polkit-policy-default.c			\
	polkit-debug.h				polkit-debug.c				\
	polkit-utils.h				polkit-utils.c				\
	polkit-config.h				polkit-config.c				\
	polkit-authorization.h			polkit-authorization.c			\
	polkit-authorization-constraint.h	polkit-authorization-constraint.c	\
	polkit-authorization-db.h

if POLKIT_AUTHDB_DUMMY
libpolkit_la_SOURCES +=                                					\
						polkit-authorization-db-dummy.c
endif

if POLKIT_AUTHDB_DEFAULT
libpolkit_la_SOURCES +=                                					\
						polkit-authorization-db.c
endif

libpolkit_la_LIBADD = @GLIB_LIBS@ @EXPAT_LIBS@

libpolkit_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if POLKIT_BUILD_TESTS
TESTS_ENVIRONMENT=
TESTS=polkit-test

if POLKIT_GCOV_ENABLED
clean-gcov:
	rm -f *.gcov .libs/*.gcda

.PHONY: coverage-report.txt
coverage-report.txt :
	$(top_srcdir)/test/create-coverage-report.sh polkit $(filter %.c,$(libpolkit_la_SOURCES)) > coverage-report.txt

check-coverage : clean-gcov all check coverage-report.txt
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

## we use noinst_PROGRAMS not check_PROGRAMS so that we build 
## even when not doing "make check"
noinst_PROGRAMS=$(TESTS)

polkit_test_SOURCES=				\
	polkit-test.h		polkit-test.c

polkit_test_LDADD=$(top_builddir)/polkit/libpolkit.la
polkit_test_LDFLAGS=
#@R_DYNAMIC_LDFLAG@


clean-local :
	rm -f *~ $(BUILT_SOURCES) *.bb *.bbg *.da *.gcov .libs/*.da .libs/*.bbg 

if POLKIT_AUTHDB_DEFAULT
# The directories /var/lib/PolicyKit and /var/run/PolicyKit is where
# authorizations are stored. They must not be world readable (the
# polkit-auth-read-helper is used to read it) and the $POLKIT_GROUP
# group needs to be able to write files there.
#
# The /var/lib/misc/PolicyKit.reload file is used for triggering that
# authorizations have changed; it needs to be world readable and
# writeable for the $POLKIT_GROUP group (FHS 2.3 suggests that
# location)
#
install-data-local:
	-touch $(DESTDIR)$(localstatedir)/lib/misc/PolicyKit.reload
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/misc/PolicyKit.reload
	-chmod 775 $(DESTDIR)$(localstatedir)/lib/misc/PolicyKit.reload
	-mkdir -p $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-mkdir -p $(DESTDIR)$(localstatedir)/run/PolicyKit
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/run/PolicyKit
	-chmod 770 $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-chmod 770 $(DESTDIR)$(localstatedir)/run/PolicyKit
endif

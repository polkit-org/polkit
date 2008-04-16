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
	-DTEST_DATA_DIR=\"$(top_srcdir)/test/\" \
	-DTEST_BUILD_DIR=\"$(top_builddir)\"

lib_LTLIBRARIES=libpolkit.la

libpolkitincludedir=$(includedir)/PolicyKit/polkit

libpolkitinclude_HEADERS =              		\
	polkit.h					\
	polkit-sysdeps.h				\
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

libpolkit_la_LIBADD = @EXPAT_LIBS@ $(top_builddir)/src/kit/libkit.la

libpolkit_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) @R_DYNAMIC_LDFLAG@ \
	               -export-dynamic -no-undefined -export-symbols-regex '(^polkit_.*|_pk_validate_unique_bus_name)'

## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if POLKIT_BUILD_TESTS
TESTS_ENVIRONMENT=
TESTS=polkit-test

check_PROGRAMS=$(TESTS)

polkit_test_SOURCES=				\
	polkit-test.h		polkit-test.c

polkit_test_LDADD=$(top_builddir)/src/polkit/libpolkit.la
polkit_test_LDFLAGS=

if POLKIT_GCOV_ENABLED
clean-gcov:
	rm -f *.gcov .libs/*.gcda *.gcda

.PHONY: coverage-report.txt covered-files.txt

covered-files.txt :
	echo $(addprefix src/polkit/,$(filter %.c,$(libpolkit_la_SOURCES))) > covered-files.txt

coverage-report.txt : covered-files.txt clean-gcov all check
	gcov $(filter %.c,$(libpolkit_la_SOURCES)) -o .libs/ > /dev/null
	$(top_srcdir)/test/create-coverage-report.sh "module polkit" `cat covered-files.txt` > coverage-report.txt

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
	rm -f *~ $(BUILT_SOURCES) *.bb *.bbg *.da *.gcov .libs/*.da .libs/*.bbg 

if POLKIT_AUTHDB_DEFAULT
# The directories /var/lib/PolicyKit and /var/run/PolicyKit is where
# authorizations are stored. They must not be world readable (the
# polkit-auth-read-helper is used to read it) and the $POLKIT_GROUP
# group needs to be able to write files there.
#
# The directory /var/lib/PolicyKit-public is used for storing world-readable
# information. Only $POLKIT_USER may write to it.
#
# The /var/lib/misc/PolicyKit.reload file is used for triggering that
# authorizations have changed; it needs to be world readable and
# writeable for user $POLKIT_USER and group $POLKIT_GROUP (FHS 2.3 suggests
# that location)
#
install-data-local:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/misc
	touch $(DESTDIR)$(localstatedir)/lib/misc/PolicyKit.reload
	-chown $(POLKIT_USER):$(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/misc/PolicyKit.reload
	-chmod 775 $(DESTDIR)$(localstatedir)/lib/misc/PolicyKit.reload
	mkdir -p $(DESTDIR)$(localstatedir)/lib/PolicyKit-public
	mkdir -p $(DESTDIR)$(localstatedir)/lib/PolicyKit
	mkdir -p $(DESTDIR)$(localstatedir)/run/PolicyKit
	-chown $(POLKIT_USER) $(DESTDIR)$(localstatedir)/lib/PolicyKit-public
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/run/PolicyKit
	-chmod 755 $(DESTDIR)$(localstatedir)/lib/PolicyKit-public
	-chmod 770 $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-chmod 770 $(DESTDIR)$(localstatedir)/run/PolicyKit
endif

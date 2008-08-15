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
	-DTEST_BUILD_DIR=\"$(top_builddir)\" \
	@DBUS_CFLAGS@


lib_LTLIBRARIES=libpolkit-1.la

libpolkit_1includedir=$(includedir)/polkit-1/polkit

libpolkit_1include_HEADERS =              		\
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
	polkit-action-description.h			\
	polkit-implicit-authorization.h			\
	polkit-authorization.h				\
	polkit-authorization-constraint.h		\
	polkit-authorization-db.h			\
	polkit-tracker.h				\
	polkit-simple.h

libpolkit_1_la_SOURCES =                                				\
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
	polkit-action-description.h		polkit-action-description.c		\
	polkit-implicit-authorization.h		polkit-implicit-authorization.c		\
	polkit-debug.h				polkit-debug.c				\
	polkit-utils.h				polkit-utils.c				\
	polkit-authorization.h			polkit-authorization.c			\
	polkit-authorization-constraint.h	polkit-authorization-constraint.c	\
	polkit-authorization-db.h							\
	polkit-tracker.h			polkit-tracker.c			\
	polkit-simple.h				polkit-simple.c

if POLKIT_AUTHDB_DUMMY
libpolkit_1_la_SOURCES +=                                					\
						polkit-authorization-db-dummy.c
endif

if POLKIT_AUTHDB_DEFAULT
libpolkit_1_la_SOURCES +=                                					\
						polkit-authorization-db.c
endif

libpolkit_1_la_LIBADD = @DBUS_LIBS@ @EXPAT_LIBS@ $(top_builddir)/src/kit/libkit.la $(SELINUX_LIBS)

if POLKIT_BUILD_TESTS
libpolkit_1_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) @R_DYNAMIC_LDFLAG@
else
libpolkit_1_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) @R_DYNAMIC_LDFLAG@ \
                       -export-dynamic -no-undefined -export-symbols-regex '(^polkit_.*|_pk_validate_unique_bus_name)'
endif

## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if POLKIT_BUILD_TESTS
TESTS_ENVIRONMENT=
TESTS=polkit-test

check_PROGRAMS=$(TESTS)

polkit_test_SOURCES=				\
	polkit-test.h		polkit-test.c

polkit_test_LDADD=$(top_builddir)/src/kit/libkit.la $(top_builddir)/src/polkit/libpolkit-1.la
polkit_test_LDFLAGS=

if POLKIT_GCOV_ENABLED
clean-gcov:
	rm -f *.gcov .libs/*.gcda *.gcda

.PHONY: coverage-report.txt covered-files.txt

covered-files.txt :
	echo $(addprefix src/polkit/,$(filter %.c,$(libpolkit_1_la_SOURCES))) > covered-files.txt

coverage-report.txt : covered-files.txt clean-gcov all check
	gcov $(filter %.c,$(libpolkit_1_la_SOURCES)) -o .libs/ > /dev/null
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

libexec_PROGRAMS = polkit-resolve-exe-helper-1

polkit_resolve_exe_helper_1_SOURCES = polkit-resolve-exe-helper.c
polkit_resolve_exe_helper_1_CFLAGS = @DBUS_CFLAGS@
polkit_resolve_exe_helper_1_LDADD = $(top_builddir)/src/kit/libkit.la libpolkit-1.la

if POLKIT_AUTHDB_DEFAULT
libexec_PROGRAMS += polkit-read-auth-helper-1 polkit-set-default-helper-1

polkit_read_auth_helper_1_SOURCES = polkit-read-auth-helper.c
polkit_read_auth_helper_1_CFLAGS = @DBUS_CFLAGS@
polkit_read_auth_helper_1_LDADD = $(top_builddir)/src/kit/libkit.la libpolkit-1.la

polkit_set_default_helper_1_SOURCES = polkit-set-default-helper.c
polkit_set_default_helper_1_CFLAGS = @DBUS_CFLAGS@
polkit_set_default_helper_1_LDADD = $(top_builddir)/src/kit/libkit.la libpolkit-1.la

# The directories /var/lib/polkit-1 and /var/run/polkit-1 is where
# authorizations are stored. They must not be world readable (the
# polkit-auth-read-helper is used to read it) and the $POLKIT_GROUP
# group needs to be able to write files there.
#
# The directory /var/lib/polkit-public-1 is used for storing world-readable
# information. Only $POLKIT_USER may write to it.
#
# The /var/lib/misc/polkit-1.reload file is used for triggering that
# authorizations have changed; it needs to be world readable and
# writeable for user $POLKIT_USER and group $POLKIT_GROUP (FHS 2.3 suggests
# that location)
#
# polkit-read-auth-helper needs to be setgid $POLKIT_GROUP to be able
# to read authorization files in /var/lib/polkit-1 and
# /var/run/polkit-1
#
# polkit-set-default-helper needs to be setuid $POLKIT_USER to be able
# to write .defaults-override files in /var/lib/polkit-public-1
#
# polkit-resolve-exe-helper needs to be setuid root to be able to resolve
# /proc/$pid/exe symlinks.
#
install-exec-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/misc
	touch $(DESTDIR)$(localstatedir)/lib/misc/polkit-1.reload
	-chown $(POLKIT_USER):$(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/misc/polkit-1.reload
	-chmod 664 $(DESTDIR)$(localstatedir)/lib/misc/polkit-1.reload
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-public-1
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(localstatedir)/run/polkit-1
	-chown $(POLKIT_USER) $(DESTDIR)$(localstatedir)/lib/polkit-public-1
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/run/polkit-1
	-chmod 755 $(DESTDIR)$(localstatedir)/lib/polkit-public-1
	-chmod 770 $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chmod 770 $(DESTDIR)$(localstatedir)/run/polkit-1
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-read-auth-helper-1
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-read-auth-helper-1
	-chown $(POLKIT_USER) $(DESTDIR)$(libexecdir)/polkit-set-default-helper-1
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-set-default-helper-1
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-resolve-exe-helper-1
else
install-exec-hook:
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-resolve-exe-helper
endif

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
	@DBUS_CFLAGS@

lib_LTLIBRARIES=libpolkit-dbus.la

libpolkit_dbusincludedir=$(includedir)/PolicyKit/polkit-dbus

libpolkit_dbusinclude_HEADERS =              			\
	polkit-dbus.h						\
	polkit-simple.h

libpolkit_dbus_la_SOURCES =                                	\
	polkit-dbus.h		polkit-dbus.c			\
	polkit-simple.h		polkit-simple.c

libpolkit_dbus_la_LIBADD = @DBUS_LIBS@ $(top_builddir)/src/polkit/libpolkit.la $(SELINUX_LIBS)

libpolkit_dbus_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) @R_DYNAMIC_LDFLAG@

libexec_PROGRAMS = polkit-resolve-exe-helper

polkit_resolve_exe_helper_SOURCES = polkit-resolve-exe-helper.c
polkit_resolve_exe_helper_CFLAGS = @DBUS_CFLAGS@
polkit_resolve_exe_helper_LDADD = $(top_builddir)/src/polkit/libpolkit.la libpolkit-dbus.la

if POLKIT_AUTHDB_DEFAULT
libexec_PROGRAMS += polkit-read-auth-helper polkit-set-default-helper

polkit_read_auth_helper_SOURCES = polkit-read-auth-helper.c
polkit_read_auth_helper_CFLAGS = @DBUS_CFLAGS@
polkit_read_auth_helper_LDADD = $(top_builddir)/src/polkit/libpolkit.la libpolkit-dbus.la

polkit_set_default_helper_SOURCES = polkit-set-default-helper.c
polkit_set_default_helper_CFLAGS = @DBUS_CFLAGS@
polkit_set_default_helper_LDADD = $(top_builddir)/src/polkit/libpolkit.la libpolkit-dbus.la

# polkit-read-auth-helper needs to be setgid $POLKIT_GROUP to be able
# to read authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
# polkit-set-default-helper needs to be setgid $POLKIT_GROUP to be able
# to write .override files in /var/lib/PolicyKit-public
#
# polkit-resolve-exe-helper needs to be setuid root to be able to resolve
# /proc/$pid/exe symlinks.
#
install-exec-hook:
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-read-auth-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-read-auth-helper
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-set-default-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-set-default-helper
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-resolve-exe-helper
else
install-exec-hook:
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-resolve-exe-helper
endif


## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if KIT_BUILD_TESTS
TESTS_ENVIRONMENT=
TESTS=polkit-dbus-test

check_PROGRAMS=$(TESTS)

polkit_dbus_test_SOURCES=				\
	polkit-dbus-test.h	polkit-dbus-test.c

polkit_dbus_test_LDADD=$(top_builddir)/src/polkit-dbus/libpolkit-dbus.la
polkit_dbus_test_LDFLAGS=

if KIT_GCOV_ENABLED
clean-gcov:
	rm -f *.gcov .libs/*.gcda *.gcda

.PHONY: coverage-report.txt covered-files.txt

covered-files.txt :
	echo $(addprefix src/polkit-dbus/,$(filter %.c,$(libpolkit_dbus_la_SOURCES))) > covered-files.txt
if POLKIT_AUTHDB_DEFAULT
	echo src/polkit-dbus/polkit-read-auth-helper.c >> covered-files.txt
endif

coverage-report.txt : covered-files.txt clean-gcov all check 
	gcov $(filter %.c,$(libpolkit_dbus_la_SOURCES)) -o .libs/ > /dev/null
if POLKIT_AUTHDB_DEFAULT
	gcov polkit-read-auth-helper.c -o .libs/ > /dev/null
endif
	$(top_srcdir)/test/create-coverage-report.sh "module polkit-dbus" `cat covered-files.txt` > coverage-report.txt

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

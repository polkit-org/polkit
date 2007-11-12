## Process this file with automake to produce Makefile.in

NULL =

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
	-DKIT_COMPILATION \
	@GLIB_CFLAGS@

noinst_LTLIBRARIES=libkit.la


libkit_la_SOURCES =					\
	kit.h						\
	kit-test.h		kit-test.c		\
	kit-memory.h		kit-memory.c		\
	kit-string.h		kit-string.c		\
	kit-list.h		kit-list.c		\
	kit-hash.h		kit-hash.c		\
	kit-file.h		kit-file.c		\
	kit-spawn.h		kit-spawn.c		\
	kit-message.h		kit-message.c		\
	$(NULL)


## note that TESTS has special meaning (stuff to use in make check)
## so if adding tests not to be run in make check, don't add them to 
## TESTS
if KIT_BUILD_TESTS
TESTS_ENVIRONMENT=
TESTS=kit-test

if KIT_GCOV_ENABLED
clean-gcov:
	rm -f *.gcov .libs/*.gcda

.PHONY: coverage-report.txt covered-files.txt

covered-files.txt :
	echo $(addprefix src/kit/,$(filter %.c,$(libkit_la_SOURCES))) > covered-files.txt

coverage-report.txt : covered-files.txt clean-gcov all check 
	gcov $(filter %.c,$(libkit_la_SOURCES)) -o .libs/ > /dev/null
	$(top_srcdir)/test/create-coverage-report.sh "module kit" `cat covered-files.txt` > coverage-report.txt

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

## we use noinst_PROGRAMS not check_PROGRAMS so that we build 
## even when not doing "make check"
noinst_PROGRAMS=$(TESTS)

kit_test_SOURCES=				\
	kit-test-main.c

kit_test_LDADD=$(top_builddir)/src/kit/libkit.la
kit_test_LDFLAGS=

clean-local :
	rm -f *~ *.bb *.bbg *.da *.gcov .libs/*.da .libs/*.bbg 


NULL =

AM_CPPFLAGS =                                              	\
	-I$(top_builddir)/src                           	\
	-I$(top_srcdir)/src                             	\
	-I$(top_srcdir)/test                             	\
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\"       	\
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\"       	\
	-DPACKAGE_DATA_DIR=\""$(datadir)"\"             	\
	-DPACKAGE_BIN_DIR=\""$(bindir)"\"               	\
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" 	\
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\"         	\
	-DPACKAGE_LIB_DIR=\""$(libdir)"\"               	\
	-D_POSIX_PTHREAD_SEMANTICS                      	\
	-D_REENTRANT	                                	\
	$(NULL)

AM_CFLAGS =							\
        -D_POLKIT_COMPILATION                                   \
        -D_POLKIT_BACKEND_COMPILATION                           \
	$(GLIB_CFLAGS)						\
	$(NULL)

LDADD =  	                      				\
	$(GLIB_LIBS)						\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la	\
	$(top_builddir)/src/polkitbackend/libpolkit-backend-1.la\
	$(top_builddir)/test/libpolkit-test-helper.la           \
	$(NULL)

TEST_PROGS =

# ----------------------------------------------------------------------------------------------------

polkitbackendjsauthoritytest_SOURCES =           \
	test-polkitbackendjsauthority.c          \
	polkitbackendjsauthoritytest-wrapper.py

# force C++ link via dummy C++ file, (see GNU automake manual section 8.3.5)
nodist_EXTRA_polkitbackendjsauthoritytest_SOURCES = dummy-force-cpp-link.cxx

TESTS_ENVIRONMENT = TOP_BUILD_DIR="$(top_builddir)"
TEST_PROGS += polkitbackendjsauthoritytest-wrapper.py

# ----------------------------------------------------------------------------------------------------

noinst_PROGRAMS = polkitbackendjsauthoritytest
TESTS = $(TEST_PROGS)

EXTRA_DIST = meson.build

clean-local :
	rm -f *~

-include $(top_srcdir)/git.mk

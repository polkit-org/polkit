
NULL =

INCLUDES =                                              	\
	-I$(top_builddir)/src                           	\
	-I$(top_builddir)/test                          	\
	-I$(top_srcdir)/src                             	\
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

TEST_PROGS += polkitbackendlocalauthorizationstoretest
polkitbackendlocalauthorizationstoretest_SOURCES = polkitbackendlocalauthorizationstoretest.c

TEST_PROGS += polkitbackendlocalauthoritytest
polkitbackendlocalauthoritytest_SOURCES = polkitbackendlocalauthoritytest.c

# ----------------------------------------------------------------------------------------------------

check_PROGRAMS = $(TEST_PROGS)
TESTS = $(TEST_PROGS)

clean-local :
	rm -f *~

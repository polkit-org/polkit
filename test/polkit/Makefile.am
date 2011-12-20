
NULL =

INCLUDES =                                              	\
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

AM_CFLAGS =            				\
	-D_POLKIT_COMPILATION                                   \
	-D_POLKIT_BACKEND_COMPILATION                           \
	$(GLIB_CFLAGS)						\
	$(NULL)

LDADD =  	                      		\
	$(GLIB_LIBS)						\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la	\
	$(NULL)

TEST_PROGS =

# ----------------------------------------------------------------------------------------------------

TEST_PROGS += polkitunixusertest
polkitunixusertest_SOURCES = polkitunixusertest.c

TEST_PROGS += polkitunixgrouptest
polkitunixgrouptest_SOURCES = polkitunixgrouptest.c

TEST_PROGS += polkitunixnetgrouptest
polkitunixnetgrouptest_SOURCES = polkitunixnetgrouptest.c

TEST_PROGS += polkitidentitytest
polkitidentitytest_SOURCES = polkitidentitytest.c

# ----------------------------------------------------------------------------------------------------

check_PROGRAMS = $(TEST_PROGS)
TESTS = $(TEST_PROGS)

clean-local :
	rm -f *~

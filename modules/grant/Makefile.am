## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	@GLIB_CFLAGS@ @DBUS_CFLAGS@

polkitmoduledir = $(libdir)/PolicyKit/modules
polkitmodule_LTLIBRARIES = 			\
	polkit-module-grant.la			\
	$(NULL)


polkit_module_grant_la_SOURCES = polkit-module-grant.c
polkit_module_grant_la_LDFLAGS = -no-undefined -module -avoid-version
polkit_module_grant_la_LIBADD = $(top_builddir)/libpolkit/libpolkit.la @GLIB_LIBS@

clean-local :
	rm -f *~

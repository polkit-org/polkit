## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	@DBUS_CFLAGS@

polkitmoduledir = $(libdir)/PolicyKit/modules
polkitmodule_LTLIBRARIES = 				\
	polkit-module-default.la			\
	$(NULL)


polkit_module_default_la_SOURCES = polkit-module-default.c
polkit_module_default_la_LDFLAGS = -no-undefined -module -avoid-version
polkit_module_default_la_LIBADD = $(top_builddir)/polkit/libpolkit.la

clean-local :
	rm -f *~

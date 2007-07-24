## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	@GLIB_CFLAGS@ @DBUS_CFLAGS@

lib_LTLIBRARIES=libpolkit-dbus.la

libpolkit_dbusincludedir=$(includedir)/PolicyKit/polkit-dbus

libpolkit_dbusinclude_HEADERS =              			\
	polkit-dbus.h

libpolkit_dbus_la_SOURCES =                                	\
	polkit-dbus.h		polkit-dbus.c

libpolkit_dbus_la_LIBADD = @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(SELINUX_LIBS)

libpolkit_dbus_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

clean-local :
	rm -f *~ $(BUILT_SOURCES)


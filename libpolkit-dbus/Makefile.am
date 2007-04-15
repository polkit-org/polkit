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

libpolkit_dbusincludedir=$(includedir)/PolicyKit/libpolkit-dbus

libpolkit_dbusinclude_HEADERS =              			\
	libpolkit-dbus.h

libpolkit_dbus_la_SOURCES =                                	\
	libpolkit-dbus.h		libpolkit-dbus.c

libpolkit_dbus_la_LIBADD = @DBUS_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

libpolkit_dbus_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

clean-local :
	rm -f *~ $(BUILT_SOURCES)


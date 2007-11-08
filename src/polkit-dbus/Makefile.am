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
	@GLIB_CFLAGS@ @DBUS_CFLAGS@

lib_LTLIBRARIES=libpolkit-dbus.la

libpolkit_dbusincludedir=$(includedir)/PolicyKit/polkit-dbus

libpolkit_dbusinclude_HEADERS =              			\
	polkit-dbus.h

libpolkit_dbus_la_SOURCES =                                	\
	polkit-dbus.h		polkit-dbus.c

libpolkit_dbus_la_LIBADD = @DBUS_LIBS@ $(top_builddir)/src/polkit/libpolkit.la $(SELINUX_LIBS)

libpolkit_dbus_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if POLKIT_AUTHDB_DEFAULT
libexec_PROGRAMS = polkit-read-auth-helper

polkit_read_auth_helper_SOURCES = polkit-read-auth-helper.c
polkit_read_auth_helper_CFLAGS = @DBUS_CFLAGS@
polkit_read_auth_helper_LDADD = $(top_builddir)/src/polkit/libpolkit.la $(top_builddir)/src/polkit-dbus/libpolkit-dbus.la

# polkit-read-auth-helper needs to be setgid $POLKIT_GROUP to be able
# to read authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
install-exec-hook:
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-read-auth-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-read-auth-helper
endif

clean-local :
	rm -f *~ $(BUILT_SOURCES)

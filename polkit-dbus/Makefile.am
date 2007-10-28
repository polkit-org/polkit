## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
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

libexec_PROGRAMS = polkit-explicit-grant-helper polkit-revoke-helper polkit-read-auth-helper

polkit_explicit_grant_helper_SOURCES = polkit-explicit-grant-helper.c
polkit_explicit_grant_helper_CFLAGS = @DBUS_CFLAGS@
polkit_explicit_grant_helper_LDADD = $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_revoke_helper_SOURCES = polkit-revoke-helper.c
polkit_revoke_helper_CFLAGS = @DBUS_CFLAGS@
polkit_revoke_helper_LDADD = $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_read_auth_helper_SOURCES = polkit-read-auth-helper.c
polkit_read_auth_helper_CFLAGS = @DBUS_CFLAGS@
polkit_read_auth_helper_LDADD = $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

clean-local :
	rm -f *~ $(BUILT_SOURCES)

# polkit-explicit-grant-helper needs to be setgid $POLKIT_GROUP to be
# able to edit authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
# polkit-revoke-helper needs to be setgid $POLKIT_GROUP to be able to
# edit authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
# polkit-read-auth-helper needs to be setgid $POLKIT_GROUP to be able
# to read authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
install-exec-hook:
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-explicit-grant-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-explicit-grant-helper
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-revoke-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-revoke-helper
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-read-auth-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-read-auth-helper

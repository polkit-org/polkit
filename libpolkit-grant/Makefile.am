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

lib_LTLIBRARIES=libpolkit-grant.la

libpolkit_grantincludedir=$(includedir)/PolicyKit/libpolkit-grant

libpolkit_grantinclude_HEADERS =              			\
	libpolkit-grant.h

libpolkit_grant_la_SOURCES =      				\
	libpolkit-grant.h		libpolkit-grant.c

libpolkit_grant_la_LIBADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

libpolkit_grant_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

libexec_PROGRAMS = polkit-grant-helper

polkit_grant_helper_SOURCES = polkit-grant-helper.c
polkit_grant_helper_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ @AUTH_LIBS@ $(top_builddir)/libpolkit/libpolkit.la $(top_builddir)/libpolkit-dbus/libpolkit-dbus.la

polkit_grant_alwaysdir = $(localstatedir)/lib/PolicyKit
dist_polkit_grant_always_DATA =

polkit_grant_sessiondir = $(localstatedir)/run/PolicyKit
dist_polkit_grant_session_DATA =


clean-local :
	rm -f *~ $(BUILT_SOURCES)

# Hmm.. we could make the directories 750 and require that all mechanisms using
# libpolkit (e.g. with a need for polkit-module-grant.so to look there) just
# be part of $(POLKIT_GROUP)...
#
install-data-local:
	-chown :$(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-grant-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-grant-helper
	-chown $(POLKIT_USER):$(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-chown $(POLKIT_USER):$(POLKIT_GROUP) $(DESTDIR)$(localstatedir)/run/PolicyKit
	-chmod 775 $(DESTDIR)$(localstatedir)/lib/PolicyKit
	-chmod 775 $(DESTDIR)$(localstatedir)/run/PolicyKit

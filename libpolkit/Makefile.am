## Process this file with automake to produce Makefile.in

INCLUDES = \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	-DDBUS_API_SUBJECT_TO_CHANGE \
	@GLIB_CFLAGS@ \
	@DBUS_GLIB_CFLAGS@

lib_LTLIBRARIES=libpolkit.la libpolkit-grant.la

libpolkitincludedir=$(includedir)/libpolkit

libpolkitinclude_HEADERS =                            \
	libpolkit.h

libpolkit_la_SOURCES =                                \
	libpolkit.c           libpolkit.h

libpolkit_la_LIBADD = @DBUS_GLIB_LIBS@ @GLIB_LIBS@

libpolkit_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)


libpolkit_grantincludedir=$(includedir)/libpolkit

libpolkit_grantinclude_HEADERS =                            \
	libpolkit-grant.h

libpolkit_grant_la_SOURCES =                                \
	libpolkit-grant.c               libpolkit-grant.h               \
					polkit-interface-manager-glue.h \
					polkit-interface-session-glue.h

libpolkit_grant_la_LIBADD = @DBUS_GLIB_LIBS@ @GLIB_LIBS@

libpolkit_grant_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

polkit-interface-manager-glue.h: ../polkit-interface-manager.xml Makefile.am
	dbus-binding-tool --prefix=polkit_manager --mode=glib-client --output=polkit-interface-manager-glue.h ../polkit-interface-manager.xml

polkit-interface-session-glue.h: ../polkit-interface-session.xml Makefile.am
	dbus-binding-tool --prefix=polkit_session --mode=glib-client --output=polkit-interface-session-glue.h ../polkit-interface-session.xml

BUILT_SOURCES = polkit-interface-manager-glue.h polkit-interface-session-glue.h

clean-local :
	rm -f *~ $(BUILT_SOURCES)


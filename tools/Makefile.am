## Process this file with automake to produce Makefile.in

INCLUDES = \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-I$(top_srcdir) \
	-DDBUS_API_SUBJECT_TO_CHANGE \
	@GLIB_CFLAGS@ \
	@DBUS_CFLAGS@

bin_PROGRAMS =                    \
	polkit-is-privileged      \
	polkit-list-privileges    \
	polkit-grant-privilege

polkit_is_privileged_SOURCES = polkit-is-privileged.c
polkit_is_privileged_LDADD = @DBUS_CFLAGS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

polkit_list_privileges_SOURCES = polkit-list-privileges.c
polkit_list_privileges_LDADD = @DBUS_CFLAGS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

polkit-interface-manager-glue.h: ../polkit-interface-manager.xml Makefile.am
	dbus-binding-tool --prefix=polkit_manager --mode=glib-client --output=polkit-interface-manager-glue.h ../polkit-interface-manager.xml

polkit-interface-session-glue.h: ../polkit-interface-session.xml Makefile.am
	dbus-binding-tool --prefix=polkit_session --mode=glib-client --output=polkit-interface-session-glue.h ../polkit-interface-session.xml

polkit_grant_privilege_SOURCES= \
	polkit-grant-privilege.c					\
					polkit-interface-manager-glue.h \
					polkit-interface-session-glue.h

polkit_grant_privilege_LDADD= @DBUS_GLIB_LIBS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

BUILT_SOURCES = polkit-interface-manager-glue.h polkit-interface-session-glue.h

clean-local :
	rm -f *~ $(BUILT_SOURCES)


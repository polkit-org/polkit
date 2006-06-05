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
	polkit-grant-privilege	  \
	polkit-revoke-privilege

polkit_is_privileged_SOURCES = polkit-is-privileged.c
polkit_is_privileged_LDADD = @DBUS_CFLAGS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

polkit_list_privileges_SOURCES = polkit-list-privileges.c
polkit_list_privileges_LDADD = @DBUS_CFLAGS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

polkit_grant_privilege_SOURCES= \
	polkit-grant-privilege.c

polkit_grant_privilege_LDADD= @DBUS_GLIB_LIBS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la $(top_builddir)/libpolkit/libpolkit-grant.la

polkit_revoke_privilege_SOURCES= \
	polkit-revoke-privilege.c
polkit_revoke_privilege_LDADD= @DBUS_GLIB_LIBS@ @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

clean-local :
	rm -f *~


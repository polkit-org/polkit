## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	@GLIB_CFLAGS@ \
	@DBUS_CFLAGS@

bin_PROGRAMS = polkit-check-caller polkit-check-session polkit-policy-file-validate polkit-grant polkit-list-actions

bin_SCRIPTS = polkit-reload-config

polkit_check_caller_SOURCES = polkit-check-caller.c
polkit_check_caller_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_check_session_SOURCES = polkit-check-session.c
polkit_check_session_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_policy_file_validate_SOURCES = polkit-policy-file-validate.c
polkit_policy_file_validate_LDADD = $(top_builddir)/polkit/libpolkit.la

polkit_grant_SOURCES = polkit-grant.c
polkit_grant_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-grant/libpolkit-grant.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_list_actions_SOURCES = polkit-list-actions.c
polkit_list_actions_LDADD = $(GLIB) $(top_builddir)/polkit/libpolkit.la

polkit-reload-config: polkit-reload-config.in Makefile
	$(edit) $< >$@

EXTRA_DIST = polkit-reload-config.in

edit = sed \
	-e 's|@docdir[@]|$(docdir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@datadir[@]|$(datadir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g'

clean-local :
	rm -f *~ polkit-reload-config

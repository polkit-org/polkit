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

bin_PROGRAMS = polkit-check-caller polkit-check-session polkit-policy-file-validate polkit-grant

polkit_check_caller_SOURCES = polkit-check-caller.c
polkit_check_caller_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_check_session_SOURCES = polkit-check-session.c
polkit_check_session_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_policy_file_validate_SOURCES = polkit-policy-file-validate.c
polkit_policy_file_validate_LDADD = $(top_builddir)/polkit/libpolkit.la

polkit_grant_SOURCES = polkit-grant.c
polkit_grant_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-grant/libpolkit-grant.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

clean-local :
	rm -f *~


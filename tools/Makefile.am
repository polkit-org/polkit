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

bin_PROGRAMS = polkit-check-caller polkit-check-session polkit-privilege-file-validate

polkit_check_caller_SOURCES = polkit-check-caller.c
polkit_check_caller_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

polkit_check_session_SOURCES = polkit-check-session.c
polkit_check_session_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

polkit_privilege_file_validate_SOURCES = polkit-privilege-file-validate.c
polkit_privilege_file_validate_LDADD = @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

clean-local :
	rm -f *~


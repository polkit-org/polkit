## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	@GLIB_CFLAGS@ \
	@DBUS_CFLAGS@

bin_PROGRAMS = polkit-policy-file-validate-1 polkit-action-1 polkit-auth-1

polkit_policy_file_validate_1_SOURCES = polkit-policy-file-validate.c
polkit_policy_file_validate_1_LDADD = $(top_builddir)/src/kit/libkit.la $(top_builddir)/src/polkit/libpolkit-1.la

polkit_auth_1_SOURCES = polkit-auth.c
polkit_auth_1_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/src/polkit/libpolkit-1.la $(top_builddir)/src/polkit-grant/libpolkit-grant-1.la

polkit_action_1_SOURCES = polkit-action.c
polkit_action_1_LDADD = $(top_builddir)/src/kit/libkit.la $(top_builddir)/src/polkit/libpolkit-1.la

profiledir = $(sysconfdir)/profile.d
profile_SCRIPTS = polkit-bash-completion-1.sh

EXTRA_DIST = $(profile_SCRIPTS)

clean-local :
	rm -f *~ polkit-reload-config

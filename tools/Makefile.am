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

bin_PROGRAMS = polkit-config-file-validate polkit-policy-file-validate polkit-action polkit-auth

polkit_config_file_validate_SOURCES = polkit-config-file-validate.c
polkit_config_file_validate_LDADD = $(top_builddir)/src/kit/libkit.la $(top_builddir)/src/polkit/libpolkit.la

polkit_policy_file_validate_SOURCES = polkit-policy-file-validate.c
polkit_policy_file_validate_LDADD = $(top_builddir)/src/kit/libkit.la $(top_builddir)/src/polkit/libpolkit.la

polkit_auth_SOURCES = polkit-auth.c
polkit_auth_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/src/polkit/libpolkit.la $(top_builddir)/src/polkit-grant/libpolkit-grant.la $(top_builddir)/src/polkit-dbus/libpolkit-dbus.la

polkit_action_SOURCES = polkit-action.c
polkit_action_LDADD = $(top_builddir)/src/polkit/libpolkit.la

profiledir = $(sysconfdir)/profile.d
profile_SCRIPTS = polkit-bash-completion.sh

EXTRA_DIST = $(profile_SCRIPTS)

clean-local :
	rm -f *~ polkit-reload-config

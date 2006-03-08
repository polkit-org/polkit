## Process this file with automake to produce Makefile.in

INCLUDES = \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-I$(top_srcdir) \
	@GLIB_CFLAGS@

bin_PROGRAMS =                    \
	polkit-is-privileged

polkit_is_privileged_SOURCES = polkit-is-privileged.c
polkit_is_privileged_LDADD = @GLIB_LIBS@ $(top_builddir)/libpolkit/libpolkit.la

clean-local :
	rm -f *~

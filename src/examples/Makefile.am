
NULL =
AM_CFLAGS = -std=gnu99 $(WARN_CFLAGS)

AM_CPPFLAGS =                                              	\
	-I$(top_builddir)/src                           	\
	-I$(top_srcdir)/src                             	\
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\"       	\
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\"       	\
	-DPACKAGE_DATA_DIR=\""$(datadir)"\"             	\
	-DPACKAGE_BIN_DIR=\""$(bindir)"\"               	\
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" 	\
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\"         	\
	-DPACKAGE_LIB_DIR=\""$(libdir)"\"               	\
	-D_POSIX_PTHREAD_SEMANTICS                      	\
	-D_REENTRANT	                                	\
	$(NULL)

bin_PROGRAMS =
noinst_PROGRAMS =

# ----------------------------------------------------------------------------------------------------

noinst_PROGRAMS += cancel

cancel_SOURCES = cancel.c

cancel_CFLAGS =                             			\
	$(GLIB_CFLAGS)						\
	$(NULL)

cancel_LDADD =  	                      			\
	$(GLIB_LIBS)						\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la	\
	$(NULL)

# ----------------------------------------------------------------------------------------------------

bin_PROGRAMS += pk-example-frobnicate

pk_example_frobnicate_SOURCES = frobnicate.c

pk_example_frobnicate_CFLAGS =                             	\
	$(GLIB_CFLAGS)						\
	$(NULL)

pk_example_frobnicate_LDADD =  	                      		\
	$(GLIB_LIBS)						\
	$(NULL)

polkit_actiondir = $(datadir)/polkit-1/actions
polkit_action_in_files = org.freedesktop.policykit.examples.pkexec.policy.in
dist_polkit_action_DATA = $(polkit_action_in_files:.policy.in=.policy)

org.freedesktop.policykit.examples.pkexec.policy: org.freedesktop.policykit.examples.pkexec.policy.in
	$(AM_V_GEN) GETTEXTDATADIR=$(top_srcdir)/gettext $(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@

#check:
#       $(top_builddir)/tools/polkit-policy-file-validate-1 $(top_srcdir)/policy/$(dist_polkit_action_DATA)

DISTCLEANFILES = org.freedesktop.policykit.examples.pkexec.policy

EXTRA_DIST =							\
	org.freedesktop.policykit.examples.pkexec.policy.in	\
	meson.build						\
	$(NULL)

# ----------------------------------------------------------------------------------------------------

clean-local :
	rm -f *~

-include $(top_srcdir)/git.mk

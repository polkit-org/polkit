
NULL =

INCLUDES =                                              	\
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

dist_polkit_action_DATA = org.freedesktop.policykit.examples.pkexec.policy

@INTLTOOL_POLICY_RULE@

#check:
#       $(top_builddir)/tools/polkit-policy-file-validate-1 $(top_srcdir)/policy/$(dist_polkit_action_DATA)

DISTCLEANFILES = org.freedesktop.policykit.examples.pkexec.policy

EXTRA_DIST = org.freedesktop.policykit.examples.pkexec.policy.in

# ----------------------------------------------------------------------------------------------------

clean-local :
	rm -f *~


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

# ----------------------------------------------------------------------------------------------------

bin_PROGRAMS = pkexec pkcheck pkaction

# ----------------------------------------------------------------------------------------------------

pkexec_SOURCES = pkexec.c

pkexec_CFLAGS =                             				\
	$(GLIB_CFLAGS)							\
	$(NULL)

pkexec_LDADD =  	                      				\
	$(GLIB_LDADD)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(NULL)

polkitmodulesdir = $(libdir)/polkit-1/extensions
polkitmodules_LTLIBRARIES = libpkexec-action-lookup.la

libpkexec_action_lookup_la_SOURCES =                    		\
	pkexec-action-lookup.c                             		\
        $(NULL)

libpkexec_action_lookup_la_CFLAGS =                      		\
        -DPOLKIT_BACKEND_I_KNOW_API_IS_SUBJECT_TO_CHANGE    		\
        -DG_LOG_DOMAIN=\"pkexec-action-lookup\"        			\
	$(GLIB_CFLAGS)							\
        $(NULL)

libpkexec_action_lookup_la_LDFLAGS =                  			\
	-export_dynamic -avoid-version -module -no-undefined 		\
	-export-symbols-regex '^g_io_module_(load|unload)' 		\
        $(NULL)

libpkexec_action_lookup_la_LIBADD =                 			\
	$(top_builddir)/src/polkitbackend/libpolkit-backend-1.la	\
        $(NULL)

# ----------------------------------------------------------------------------------------------------

pkcheck_SOURCES = pkcheck.c

pkcheck_CFLAGS =                             				\
	$(GLIB_CFLAGS)							\
	$(NULL)

pkcheck_LDADD =  	                      				\
	$(GLIB_LDADD)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(NULL)

# ----------------------------------------------------------------------------------------------------

pkaction_SOURCES = pkaction.c

pkaction_CFLAGS =                             				\
	$(GLIB_CFLAGS)							\
	$(NULL)

pkaction_LDADD =  	                      				\
	$(GLIB_LDADD)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(NULL)

# ----------------------------------------------------------------------------------------------------

clean-local :
	rm -f *~

install-exec-hook :
	-chmod 4755 $(DESTDIR)$(bindir)/pkexec

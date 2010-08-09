
NULL =

module_flags = -export_dynamic -avoid-version -module -no-undefined -export-symbols-regex '^g_io_module_(load|unload)'

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
	-D_POLKIT_BACKEND_COMPILATION				\
	$(NULL)

polkitmodulesdir = $(libdir)/polkit-1/extensions
polkitmodules_LTLIBRARIES = libnullbackend.la

libnullbackend_la_SOURCES = 						\
	nullbackend.c							\
	polkitbackendnullauthority.c	polkitbackendnullauthority.h	\
	$(NULL)

libnullbackend_la_CFLAGS =                             			\
	-DPOLKIT_BACKEND_I_KNOW_API_IS_SUBJECT_TO_CHANGE		\
	-DG_LOG_DOMAIN=\"PolkitNullBackend\"				\
	$(GLIB_CFLAGS)							\
	$(NULL)

libnullbackend_la_LDFLAGS =  	                      			\
	$(module_flags)               					\
	$(GLIB_LIBS)							\
	$(top_builddir)/src/polkitbackend/libpolkit-backend-1.la	\
	$(NULL)

libnullbackend_la_LIBADD =  	                      			\
	$(NULL)

nullconfigdir = $(sysconfdir)/polkit-1/nullbackend.conf.d
nullconfig_DATA = 50-nullbackend.conf

EXTRA_DIST = $(nullconfig_DATA)

clean-local :
	rm -f *~

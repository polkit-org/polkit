NULL =

INCLUDES =                                              		\
	-I$(top_builddir)/src                           		\
	-I$(top_srcdir)/src                             		\
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\"       		\
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\"       		\
	-DPACKAGE_DATA_DIR=\""$(datadir)"\"             		\
	-DPACKAGE_BIN_DIR=\""$(bindir)"\"               		\
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" 		\
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\"         		\
	-DPACKAGE_LIB_DIR=\""$(libdir)"\"               		\
	-D_POSIX_PTHREAD_SEMANTICS                      		\
	-D_REENTRANT	                                		\
	$(NULL)

libexec_PROGRAMS = polkitd

polkitd_SOURCES = 							\
					main.c				\
	gposixsignal.h			gposixsignal.c			\
	$(NULL)

polkitd_CFLAGS = 							\
	-DPOLKIT_BACKEND_I_KNOW_API_IS_SUBJECT_TO_CHANGE		\
	-DG_LOG_DOMAIN=\"polkitd-1\"					\
	$(GLIB_CFLAGS)							\
	$(NULL)

polkitd_LDADD = 				        		\
	$(DBUS_GLIB_LIBS)						\
	$(GLIB_LIBS)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(top_builddir)/src/polkitbackend/libpolkit-backend-1.la	\
	$(NULL)

CLEANFILES = $(BUILT_SOURCES)

clean-local :
	rm -f *~

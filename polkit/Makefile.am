## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	-DPOLKIT_COMPILATION \
	@GLIB_CFLAGS@

lib_LTLIBRARIES=libpolkit.la

libpolkitincludedir=$(includedir)/PolicyKit/polkit

libpolkitinclude_HEADERS =              		\
	polkit.h					\
	polkit-types.h					\
	polkit-error.h					\
	polkit-result.h					\
	polkit-context.h				\
	polkit-action.h					\
	polkit-resource.h				\
	polkit-seat.h					\
	polkit-session.h				\
	polkit-caller.h					\
	polkit-policy-file-entry.h			\
	polkit-policy-file.h				\
	polkit-policy-cache.h				\
	polkit-policy-default.h				\
	polkit-module.h

libpolkit_la_SOURCES =                                			\
	polkit.h							\
					polkit-types.h			\
	polkit-error.h			polkit-error.c			\
	polkit-result.h			polkit-result.c			\
	polkit-context.h		polkit-context.c		\
	polkit-action.h			polkit-action.c			\
	polkit-resource.h		polkit-resource.c		\
	polkit-seat.h			polkit-seat.c			\
	polkit-session.h		polkit-session.c		\
	polkit-caller.h			polkit-caller.c			\
	polkit-policy-file-entry.h	polkit-policy-file-entry.c	\
	polkit-policy-file.h		polkit-policy-file.c		\
	polkit-policy-cache.h		polkit-policy-cache.c		\
	polkit-policy-default.h		polkit-policy-default.c		\
	polkit-debug.h			polkit-debug.c			\
	polkit-utils.h			polkit-utils.c			\
	polkit-module.h			polkit-module.c

libpolkit_la_LIBADD = @GLIB_LIBS@ -ldl

libpolkit_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

clean-local :
	rm -f *~ $(BUILT_SOURCES)

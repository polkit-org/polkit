## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	@GLIB_CFLAGS@ @DBUS_CFLAGS@

lib_LTLIBRARIES=libpolkit.la

libpolkitincludedir=$(includedir)/PolicyKit/libpolkit

libpolkitinclude_HEADERS =              		\
	libpolkit.h					\
	libpolkit-context.h				\
	libpolkit-privilege.h				\
	libpolkit-resource.h				\
	libpolkit-seat.h				\
	libpolkit-session.h				\
	libpolkit-caller.h				\
	libpolkit-privilege-file.h

libpolkit_la_SOURCES =                  	              		\
	libpolkit.h			libpolkit.c			\
	libpolkit-context.h		libpolkit-context.c		\
	libpolkit-privilege.h		libpolkit-privilege.c		\
	libpolkit-resource.h		libpolkit-resource.c		\
	libpolkit-seat.h		libpolkit-seat.c		\
	libpolkit-session.h		libpolkit-session.c		\
	libpolkit-caller.h		libpolkit-caller.c		\
	libpolkit-privilege-file.h	libpolkit-privilege-file.c

libpolkit_la_LIBADD = @GLIB_LIBS@ @DBUS_LIBS@

libpolkit_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

clean-local :
	rm -f *~ $(BUILT_SOURCES)


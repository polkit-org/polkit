NULL =

INCLUDES =                                                      \
        -I$(top_builddir)/src                                   \
        -I$(top_srcdir)/src                                     \
        -DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\"               \
        -DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\"               \
        -DPACKAGE_DATA_DIR=\""$(datadir)"\"                     \
        -DPACKAGE_BIN_DIR=\""$(bindir)"\"                       \
        -DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\"         \
        -DPACKAGE_LOCALE_DIR=\""$(localedir)"\"                 \
        -DPACKAGE_LIB_DIR=\""$(libdir)"\"                       \
        -D_POSIX_PTHREAD_SEMANTICS                              \
        -D_REENTRANT                                            \
        $(NULL)

BUILT_SOURCES =							\
        polkitbackendstubglue.h					\
        polkitauthorityglue.h				\
        $(NULL)

polkitbackendstubglue.h: $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml Makefile.am
	dbus-binding-tool --prefix=_polkit_backend_stub --mode=glib-server --output=polkitbackendstubglue.h $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml

polkitauthorityglue.h: $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml Makefile.am
	dbus-binding-tool --mode=glib-client --output=polkitauthorityglue.h $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml

lib_LTLIBRARIES=libpolkit-gobject-1.la

libpolkit_gobject_1includedir=$(includedir)/polkit-1/polkit

libpolkit_gobject_1include_HEADERS =                        		\
        polkit.h							\
	polkitactiondescription.h					\
        polkitauthority.h						\
        polkitauthorizationclaim.h					\
        polkitauthorizationresult.h					\
	polkitbackend.h							\
        polkiterror.h							\
        polkitsubject.h							\
        polkituser.h							\
        polkitprocess.h							\
        $(NULL)

libpolkit_gobject_1_la_SOURCES =                                   	\
        polkit.h							\
        polkitauthority.h		polkitauthority.c		\
	polkitactiondescription.h	polkitactiondescription.c	\
        polkitauthorizationclaim.h	polkitauthorizationclaim.c	\
        polkitauthorizationresult.h	polkitauthorizationresult.c	\
	polkitbackend.h			polkitbackend.c			\
        polkitbackendstub.h		polkitbackendstub.c		\
        polkiterror.h			polkiterror.c			\
        polkitsubject.h			polkitsubject.c			\
        polkitlocalbackend.h		polkitlocalbackend.c		\
        polkituser.h			polkituser.c			\
        polkitprocess.h			polkitprocess.c			\
	polkitserialization.h		polkitserialization.c		\
        $(BUILT_SOURCES)						\
        $(NULL)

libpolkit_gobject_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
        $(GLIB_CFLAGS)							\
        $(GIO_CFLAGS)							\
        $(DBUS_GLIB_CFLAGS)						\
        $(NULL)

libpolkit_gobject_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
        $(GIO_LIBS)							\
        $(DBUS_GLIB_LIBS)						\
        $(NULL)

CLEANFILES = $(BUILT_SOURCES)

clean-local :
	rm -f *~

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

BUILT_SOURCES =									\
	polkitbindings.h			polkitbindings.c		\
	polkitbindingstypes.h							\
	polkitauthority.h			polkitauthority.c		\
	polkitbindingsmarshal.h			polkitbindingsmarshal.c		\
	polkitbindingsmarshal.list						\
        $(NULL)

$(BUILT_SOURCES) : Makefile.am $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml
	dbus2gobject										\
	  --namespace       "Polkit"								\
	  --dbus-namespace  "org.freedesktop.PolicyKit1"					\
	  --introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml	\
	  $(NULL)

lib_LTLIBRARIES=libpolkit-gobject-1.la

libpolkit_gobject_1includedir=$(includedir)/polkit-1/polkit

libpolkit_gobject_1include_HEADERS =                        		\
        polkit.h							\
        polkitauthoritystub.h						\
	polkitactiondescription.h					\
        polkitauthority.h						\
        polkitauthorizationclaim.h					\
        polkitauthorizationresult.h					\
        polkiterror.h							\
        polkitsubject.h							\
        polkituser.h							\
        polkitprocess.h							\
	polkitbindings.h						\
	polkitbindingstypes.h						\
	polkitauthority.h						\
        $(NULL)

libpolkit_gobject_1_la_SOURCES =                                   	\
        polkit.h							\
        polkitauthoritystub.h		polkitauthoritystub.c		\
	polkitactiondescription.h	polkitactiondescription.c	\
        polkitauthorizationclaim.h	polkitauthorizationclaim.c	\
        polkitauthorizationresult.h	polkitauthorizationresult.c	\
        polkiterror.h			polkiterror.c			\
        polkitsubject.h			polkitsubject.c			\
        polkituser.h			polkituser.c			\
        polkitprocess.h			polkitprocess.c			\
        $(BUILT_SOURCES)						\
        $(NULL)

libpolkit_gobject_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
        $(GLIB_CFLAGS)							\
        $(EGG_DBUS_CFLAGS)						\
        $(NULL)

libpolkit_gobject_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
        $(EGG_DBUS_LIBS)						\
        $(NULL)

CLEANFILES = $(BUILT_SOURCES)

clean-local :
	rm -f *~

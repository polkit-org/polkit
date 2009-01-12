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
	-DEGG_DBUS_I_KNOW_API_IS_SUBJECT_TO_CHANGE		\
        $(NULL)

lib_LTLIBRARIES=libpolkit-backend-1.la

libpolkit_backend_1includedir=$(includedir)/polkit-1/polkitbackend

libpolkit_backend_1include_HEADERS =                        		\
	polkitbackend.h							\
	polkitbackendtypes.h						\
	polkitbackendauthority.h					\
	polkitbackendlocalauthority.h					\
	polkitbackendactionpool.h					\
	polkitbackendpendingcall.h					\
	polkitbackendserver.h						\
        $(NULL)

libpolkit_backend_1_la_SOURCES =                                   	\
        polkitbackend.h							\
	polkitbackendtypes.h						\
	polkitbackendprivate.h						\
	polkitbackendauthority.h	polkitbackendauthority.c	\
	polkitbackendlocalauthority.h	polkitbackendlocalauthority.c	\
	polkitbackendactionpool.h	polkitbackendactionpool.c	\
	polkitbackendpendingcall.h	polkitbackendpendingcall.c	\
	polkitbackendserver.h		polkitbackendserver.c		\
        $(NULL)

libpolkit_backend_1_la_CFLAGS =                                        	\
        -D_POLKIT_BACKEND_COMPILATION                                  	\
        $(GLIB_CFLAGS)							\
        $(EGG_DBUS_CFLAGS)						\
        $(NULL)

libpolkit_backend_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
        $(EGG_DBUS_LIBS)						\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(EXPAT_LIBS)							\
        $(NULL)

CLEANFILES = $(BUILT_SOURCES)

clean-local :
	rm -f *~

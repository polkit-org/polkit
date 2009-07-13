NULL =

INCLUDES =                                                      \
        -I$(top_builddir)/src                                   \
        -I$(top_srcdir)/src                                     \
        -I$(top_builddir)/src/polkit                            \
        -I$(top_srcdir)/src/polkit                              \
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

lib_LTLIBRARIES=libpolkit-local-1.la

libpolkit_local_1includedir=$(includedir)/polkit-1/polkitlocal

libpolkit_local_1include_HEADERS =                        				\
	polkitlocal.h									\
	polkitlocaltypes.h								\
	polkitlocalauthority.h								\
	polkitlocalauthorization.h							\
        $(NULL)

libpolkit_local_1_la_SOURCES =                                   			\
        polkitlocal.h									\
	polkitlocaltypes.h								\
	polkitlocalprivate.h								\
	polkitlocalauthority.c			polkitlocalauthority.h			\
	polkitlocalauthorization.c		polkitlocalauthorization.h		\
        $(NULL)

libpolkit_local_1_la_CFLAGS =                                 		\
        -D_POLKIT_COMPILATION                                  		\
	-D_POLKIT_LOCAL_COMPILATION					\
        $(GLIB_CFLAGS)							\
        $(EGG_DBUS_CFLAGS)						\
        $(NULL)

libpolkit_local_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
        $(EGG_DBUS_LIBS)						\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(EXPAT_LIBS)							\
        $(NULL)

clean-local :
	rm -f *~

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

BUILT_SOURCES =										\
	_polkitactiondescription.c		_polkitactiondescription.h		\
	_polkitauthority.c			_polkitauthority.h			\
	_polkitauthorizationclaim.c		_polkitauthorizationclaim.h		\
	_polkitauthorizationresult.c		_polkitauthorizationresult.h		\
	_polkitbindings.c			_polkitbindings.h			\
	_polkitbindingsmarshal.c		_polkitbindingsmarshal.h		\
	_polkitbindingstypes.h								\
	_polkiterror.c				_polkiterror.h				\
	_polkitsubject.c			_polkitsubject.h			\
	$(NULL)

$(BUILT_SOURCES) : Makefile.am $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml
	eggdbus-binding-tool									\
	  --namespace       "_Polkit"								\
	  --dbus-namespace  "org.freedesktop.PolicyKit1"					\
	  --introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml	\
	  $(NULL)

lib_LTLIBRARIES=libpolkit-gobject-1.la

libpolkit_gobject_1includedir=$(includedir)/polkit-1/polkit

libpolkit_gobject_1include_HEADERS =                        				\
        polkit.h									\
	polkitactiondescription.h							\
	polkitauthority.h								\
	polkiterror.h									\
	polkitsubject.h									\
	polkitunixuser.h								\
	polkitunixgroup.h								\
	polkitunixprocess.h								\
	polkitsystembusname.h								\
	polkitauthorizationclaim.h							\
	polkitauthorizationresult.h							\
        $(NULL)

libpolkit_gobject_1_la_SOURCES =                                   			\
        polkit.h									\
        $(BUILT_SOURCES)								\
	polkitactiondescription.c		polkitactiondescription.h		\
	polkitauthority.c			polkitauthority.h			\
	polkiterror.c				polkiterror.h				\
	polkitsubject.c				polkitsubject.h				\
	polkitunixuser.c			polkitunixuser.h			\
	polkitunixgroup.c			polkitunixgroup.h			\
	polkitunixprocess.c			polkitunixprocess.h			\
	polkitsystembusname.c			polkitsystembusname.h			\
	polkitauthorizationclaim.c		polkitauthorizationclaim.h		\
	polkitauthorizationresult.c		polkitauthorizationresult.h		\
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

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

BUILT_SOURCES = 						\
	polkitenumtypes.c		polkitenumtypes.h	\
	$(NULL)

enum_headers = polkitcheckauthorizationflags.h polkiterror.h polkitimplicitauthorization.h polkitauthorityfeatures.h

polkitenumtypes.h: $(enum_headers) polkitenumtypes.h.template
	( top_builddir=`cd $(top_builddir) && pwd`; \
	 cd $(srcdir) && glib-mkenums --template polkitenumtypes.h.template $(enum_headers)) > \
	   polkitenumtypes.h.tmp && mv polkitenumtypes.h.tmp polkitenumtypes.h

polkitenumtypes.c: $(enum_headers) polkitenumtypes.c.template
	( top_builddir=`cd $(top_builddir) && pwd`; \
	 cd $(srcdir) && glib-mkenums --template polkitenumtypes.c.template $(enum_headers)) > \
	   polkitenumtypes.c.tmp && mv polkitenumtypes.c.tmp polkitenumtypes.c

lib_LTLIBRARIES=libpolkit-gobject-1.la

libpolkit_gobject_1includedir=$(includedir)/polkit-1/polkit

libpolkit_gobject_1include_HEADERS =                        				\
        polkit.h									\
        polkitprivate.h									\
        polkittypes.h									\
	polkitenumtypes.h								\
	polkitactiondescription.h							\
	polkitauthorityfeatures.h							\
	polkitdetails.h									\
	polkitauthority.h								\
	polkiterror.h									\
	polkitsubject.h									\
	polkitunixprocess.h								\
	polkitunixsession.h								\
	polkitsystembusname.h								\
	polkitidentity.h								\
	polkitunixuser.h								\
	polkitunixgroup.h								\
	polkitauthorizationresult.h							\
	polkitcheckauthorizationflags.h							\
	polkitimplicitauthorization.h							\
	polkittemporaryauthorization.h							\
	polkitpermission.h								\
        $(NULL)

libpolkit_gobject_1_la_SOURCES =                                   			\
	$(BUILT_SOURCES)								\
        polkit.h									\
	polkitactiondescription.c		polkitactiondescription.h		\
	polkitauthorityfeatures.h		polkitauthorityfeatures.c		\
	polkitdetails.c				polkitdetails.h				\
	polkitauthority.c			polkitauthority.h			\
	polkiterror.c				polkiterror.h				\
	polkitsubject.c				polkitsubject.h				\
	polkitunixprocess.c			polkitunixprocess.h			\
	polkitunixsession.c			polkitunixsession.h			\
	polkitsystembusname.c			polkitsystembusname.h			\
	polkitidentity.c			polkitidentity.h			\
	polkitunixuser.c			polkitunixuser.h			\
	polkitunixgroup.c			polkitunixgroup.h			\
	polkitauthorizationresult.c		polkitauthorizationresult.h		\
	polkitcheckauthorizationflags.c		polkitcheckauthorizationflags.h		\
	polkitimplicitauthorization.c		polkitimplicitauthorization.h		\
	polkittemporaryauthorization.c		polkittemporaryauthorization.h		\
	polkitpermission.c			polkitpermission.h			\
        $(NULL)

libpolkit_gobject_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
        $(GLIB_CFLAGS)							\
        $(NULL)

libpolkit_gobject_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
        $(NULL)

libpolkit_gobject_1_la_LDFLAGS = -export-symbols-regex '(^polkit_.*)'

if HAVE_INTROSPECTION
girdir = $(INTROSPECTION_GIRDIR)
gir_DATA = Polkit-1.0.gir

typelibsdir = $(INTROSPECTION_TYPELIBDIR)
typelibs_DATA = Polkit-1.0.typelib

Polkit-1.0.gir: libpolkit-gobject-1.la $(INTROSPECTION_SCANNER) Makefile.am
	$(INTROSPECTION_SCANNER) -v 				\
		--warn-all					\
		--namespace Polkit 				\
		--nsversion=1.0 				\
		--include=Gio-2.0 				\
		--library=polkit-gobject-1 			\
		--output $@ 					\
		--pkg=glib-2.0 					\
		--pkg=gobject-2.0 				\
		--pkg=gio-2.0 					\
		--pkg-export=polkit-gobject-1			\
		--libtool=$(top_builddir)/libtool		\
		--c-include='polkit/polkit.h'			\
                -I$(top_srcdir)/src	 			\
	        -D_POLKIT_COMPILATION                   	\
		$(libpolkit_gobject_1_la_SOURCES)		\
		$(NULL)

Polkit-1.0.typelib: Polkit-1.0.gir $(INTROSPECTION_COMPILER)
	$(INTROSPECTION_COMPILER) $< -o $@

endif # HAVE_INTROSPECTION

EXTRA_DIST = polkitenumtypes.h.template polkitenumtypes.c.template
CLEANFILES = $(gir_DATA) $(typelibs_DATA)

dist-hook :
	(for i in $(polkit_built_sources) $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(polkit_built_sources) $(BUILT_SOURCES)


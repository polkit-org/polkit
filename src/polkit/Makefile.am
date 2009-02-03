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

BUILT_SOURCES = 						\
	authority-built-sources.stamp				\
	$(NULL)

authority-built-sources.stamp : Makefile.am $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthorityManager.xml
	eggdbus-binding-tool										\
		--namespace "_Polkit"									\
		--dbus-namespace "org.freedesktop.PolicyKit1"						\
		--introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml 	\
		--introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthorityManager.xml	\
		--stamp-file authority-built-sources.stamp						\
	$(NULL)

# keep in sync with contents of authority-built-sources.stamp (Thanks autotools)
#
authority_built_sources = _polkitbindingsmarshal.c _polkitbindingsmarshal.h _polkitbindingsmarshal.list _polkitbindings.c _polkitbindings.h _polkitbindingstypes.h _polkitauthoritymanager.c _polkitauthoritymanager.h docbook-interface-org.freedesktop.PolicyKit1.AuthorityManager.xml _polkitauthority.c _polkitauthority.h docbook-interface-org.freedesktop.PolicyKit1.Authority.xml _polkitcheckauthorizationflags.c _polkitcheckauthorizationflags.h _polkitauthorizationresult.c _polkitauthorizationresult.h _polkiterror.c _polkiterror.h _polkitimplicitauthorization.c _polkitimplicitauthorization.h _polkitauthorization.c _polkitauthorization.h _polkitactiondescription.c _polkitactiondescription.h _polkitidentity.c _polkitidentity.h _polkitsubject.c _polkitsubject.h

lib_LTLIBRARIES=libpolkit-gobject-1.la

libpolkit_gobject_1includedir=$(includedir)/polkit-1/polkit

libpolkit_gobject_1include_HEADERS =                        				\
        polkit.h									\
        polkitprivate.h									\
        polkittypes.h									\
	polkitactiondescription.h							\
	polkitauthority.h								\
	polkitauthoritymanager.h							\
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
	polkitauthorization.h								\
	polkitimplicitauthorization.h							\
        $(NULL)

libpolkit_gobject_1_la_SOURCES =                                   			\
	$(BUILT_SOURCES)								\
	$(authority_built_sources)							\
        polkit.h									\
	polkitactiondescription.c		polkitactiondescription.h		\
	polkitauthority.c			polkitauthority.h			\
	polkitauthoritymanager.c		polkitauthoritymanager.h		\
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
	polkitauthorization.c			polkitauthorization.h			\
	polkitimplicitauthorization.c		polkitimplicitauthorization.h		\
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

dist-hook :
	(for i in $(authority_built_sources) $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(authority_built_sources) $(BUILT_SOURCES)


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
	polkit-built-sources.stamp				\
	$(NULL)

# Build all the PolicyKit D-Bus code here, even the code we
# only in the daemon for agent interaction
#
polkit-built-sources.stamp : Makefile.am $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthenticationAgent.xml
	eggdbus-binding-tool											\
		--namespace "_Polkit"										\
		--dbus-namespace "org.freedesktop.PolicyKit1"							\
		--introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.Authority.xml 		\
		--introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthenticationAgent.xml	\
		--stamp-file polkit-built-sources.stamp								\
	$(NULL)

# keep in sync with contents of polkit-built-sources.stamp (Thanks autotools)
#
polkit_built_sources = _polkitactiondescription.c _polkitactiondescription.h _polkitauthenticationagent.c _polkitauthenticationagent.h _polkitauthority.c _polkitauthority.h _polkitauthorizationresult.c _polkitauthorizationresult.h _polkitbindings.c _polkitbindings.h _polkitbindingsmarshal.c _polkitbindingsmarshal.h _polkitbindingstypes.h _polkitcheckauthorizationflags.c _polkitcheckauthorizationflags.h _polkiterror.c _polkiterror.h _polkitidentity.c _polkitidentity.h _polkitimplicitauthorization.c _polkitimplicitauthorization.h _polkitsubject.c _polkitsubject.h _polkittemporaryauthorization.c _polkittemporaryauthorization.h docbook-interface-org.freedesktop.PolicyKit1.AuthenticationAgent.xml docbook-interface-org.freedesktop.PolicyKit1.Authority.xml _polkitbindingsmarshal.list

lib_LTLIBRARIES=libpolkit-gobject-1.la

libpolkit_gobject_1includedir=$(includedir)/polkit-1/polkit

libpolkit_gobject_1include_HEADERS =                        				\
        polkit.h									\
        polkitprivate.h									\
        polkittypes.h									\
	polkitactiondescription.h							\
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
        $(NULL)

libpolkit_gobject_1_la_SOURCES =                                   			\
	$(BUILT_SOURCES)								\
	$(polkit_built_sources)								\
        polkit.h									\
	polkitactiondescription.c		polkitactiondescription.h		\
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
	(for i in $(polkit_built_sources) $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(polkit_built_sources) $(BUILT_SOURCES)


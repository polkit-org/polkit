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
        $(NULL)

BUILT_SOURCES = 						\
	marshal.stamp						\
	polkitagentenumtypes.c		polkitagentenumtypes.h	\
	$(NULL)

enum_headers = polkitagentlistener.h

polkitagentenumtypes.h: $(enum_headers) polkitagentenumtypes.h.template
	( top_builddir=`cd $(top_builddir) && pwd`; \
	 cd $(srcdir) && glib-mkenums --template polkitagentenumtypes.h.template $(enum_headers)) > \
	   polkitagentenumtypes.h.tmp && mv polkitagentenumtypes.h.tmp polkitagentenumtypes.h

polkitagentenumtypes.c: $(enum_headers) polkitagentenumtypes.c.template
	( top_builddir=`cd $(top_builddir) && pwd`; \
	 cd $(srcdir) && glib-mkenums --template polkitagentenumtypes.c.template $(enum_headers)) > \
	   polkitagentenumtypes.c.tmp && mv polkitagentenumtypes.c.tmp polkitagentenumtypes.c

marshal.stamp : Makefile.am $(srcdir)/polkitagentmarshal.list
	glib-genmarshal --prefix=_polkit_agent_marshal $(srcdir)/polkitagentmarshal.list --header > polkitagentmarshal.h.tmp && mv polkitagentmarshal.h.tmp polkitagentmarshal.h
	(echo "#include \"polkitagentmarshal.h\""; glib-genmarshal --prefix=_polkit_agent_marshal $(srcdir)/polkitagentmarshal.list --body) > polkitagentmarshal.c.tmp && mv polkitagentmarshal.c.tmp polkitagentmarshal.c
	touch marshal.stamp

marshal_built_sources = polkitagentmarshal.h polkitagentmarshal.c

lib_LTLIBRARIES=libpolkit-agent-1.la

libpolkit_agent_1includedir=$(includedir)/polkit-1/polkitagent

libpolkit_agent_1include_HEADERS =                        				\
	polkitagent.h									\
	polkitagentenumtypes.h								\
	polkitagenttypes.h								\
	polkitagentsession.h								\
	polkitagentlistener.h								\
	polkitagenttextlistener.h							\
        $(NULL)

libpolkit_agent_1_la_SOURCES =                                   			\
	$(BUILT_SOURCES)								\
	$(marshal_built_sources)							\
        polkitagent.h									\
	polkitagenttypes.h								\
	polkitagentsession.h			polkitagentsession.c			\
	polkitagentlistener.h			polkitagentlistener.c			\
	polkitagenttextlistener.h		polkitagenttextlistener.c		\
        $(NULL)

libpolkit_agent_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
	-D_POLKIT_AGENT_COMPILATION					\
        $(GLIB_CFLAGS)							\
        $(NULL)

libpolkit_agent_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(EXPAT_LIBS)							\
        $(NULL)

libpolkit_agent_1_la_LDFLAGS = -export-symbols-regex '(^polkit_.*)'

libexec_PROGRAMS = polkit-agent-helper-1

polkit_agent_helper_1_SOURCES = 					\
	polkitagenthelperprivate.c polkitagenthelperprivate.h		\
	$(NULL)

if POLKIT_AUTHFW_PAM
polkit_agent_helper_1_SOURCES += polkitagenthelper-pam.c
endif
if POLKIT_AUTHFW_SHADOW
polkit_agent_helper_1_SOURCES += polkitagenthelper-shadow.c
endif

polkit_agent_helper_1_CFLAGS  = 					\
        -D_POLKIT_COMPILATION                                  		\
	$(GLIB_CFLAGS)							\
	$(NULL)

polkit_agent_helper_1_LDADD = 						\
	$(AUTH_LIBS)							\
	$(GLIB_LIBS)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(NULL)

if HAVE_INTROSPECTION

girdir = $(INTROSPECTION_GIRDIR)
gir_DATA = PolkitAgent-1.0.gir

typelibsdir = $(INTROSPECTION_TYPELIBDIR)
typelibs_DATA = PolkitAgent-1.0.typelib

INTROSPECTION_COMPILER_ARGS = --includedir=../../src/polkit
INTROSPECTION_GIRS = PolkitAgent-1.0.gir
PolkitAgent_1_0_gir_INCLUDES = Gio-2.0
PolkitAgent_1_0_gir_SCANNERFLAGS = \
	--include-uninstalled=../../src/polkit/Polkit-1.0.gir	\
	--c-include='polkitagent/polkitagent.h'
PolkitAgent_1_0_gir_CFLAGS = \
        $(libpolkit_agent_1_la_CFLAGS)		\
        -D_POLKIT_COMPILATION			\
        -D_POLKIT_AGENT_COMPILATION		\
        -I.. -I$(top_srcdir)/src
PolkitAgent_1_0_gir_LIBS = libpolkit-agent-1.la
PolkitAgent_1_0_gir_FILES = $(libpolkit_agent_1_la_SOURCES)
PolkitAgent_1_0_gir_EXPORT_PACKAGES = polkit-agent-1

include $(INTROSPECTION_MAKEFILE)

endif # HAVE_INTROSPECTION

# polkit-agent-helper-1 need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users.
#
install-exec-hook:
	-chown root $(DESTDIR)$(libexecdir)/polkit-agent-helper-1
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-agent-helper-1

EXTRA_DIST = polkitagentmarshal.list polkitagentenumtypes.h.template polkitagentenumtypes.c.template

dist-hook :
	(for i in $(marshal_built_sources) $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(marshal_built_sources) $(BUILT_SOURCES)

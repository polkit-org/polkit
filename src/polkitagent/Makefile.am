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
	-DPOLKIT_AGENT_COMPILATION				\
	-DEGG_DBUS_I_KNOW_API_IS_SUBJECT_TO_CHANGE		\
        $(NULL)

BUILT_SOURCES =											\
	_polkitagentauthenticationagent.c		_polkitagentauthenticationagent.h	\
	_polkitagentbindings.c				_polkitagentbindings.h			\
	_polkitagentbindingsmarshal.list							\
	_polkitagentbindingsmarshal.c			_polkitagentbindingsmarshal.h		\
	_polkitagentbindingstypes.h								\
	$(NULL)

$(BUILT_SOURCES) : Makefile.am $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthenticationAgent.xml
	eggdbus-binding-tool										\
	  --namespace       "_PolkitAgent"								\
	  --dbus-namespace  "org.freedesktop.PolicyKit1"						\
	  --introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthenticationAgent.xml	\
	  $(NULL)

BUILT_SOURCES += 						\
	polkitagentmarshal.h		polkitagentmarshal.c	\
	$(NULL)

polkitagentmarshal.h : polkitagentmarshal.list
	glib-genmarshal --prefix=polkit_agent_marshal $(srcdir)/polkitagentmarshal.list --header > $@.tmp && mv $@.tmp $@

polkitagentmarshal.c: polkitagentmarshal.h polkitagentmarshal.list
	(echo "#include \"polkitagentmarshal.h\""; glib-genmarshal --prefix=polkit_agent_marshal $(srcdir)/polkitagentmarshal.list --body) > $@.tmp && mv $@.tmp $@

lib_LTLIBRARIES=libpolkit-agent-1.la

libpolkit_agent_1includedir=$(includedir)/polkit-1/polkitagent

libpolkit_agent_1include_HEADERS =                        				\
	polkitagent.h									\
	polkitagenttypes.h								\
	polkitagentsession.h								\
	polkitagentlistener.h								\
        $(NULL)

libpolkit_agent_1_la_SOURCES =                                   			\
        polkitagent.h									\
	polkitagenttypes.h								\
	polkitagentsession.h			polkitagentsession.c			\
	polkitagentlistener.h			polkitagentlistener.c			\
	$(BUILT_SOURCES)								\
        $(NULL)

libpolkit_agent_1_la_CFLAGS =                                        	\
        $(GLIB_CFLAGS)							\
        $(EGG_DBUS_CFLAGS)						\
        $(NULL)

libpolkit_agent_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
        $(EGG_DBUS_LIBS)						\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(EXPAT_LIBS)							\
        $(NULL)

libexec_PROGRAMS = polkit-agent-helper-1

polkit_agent_helper_1_SOURCES = polkitagenthelper.c
polkit_agent_helper_1_CFLAGS  = $(GLIB_CFLAGS)
polkit_agent_helper_1_LDADD   = $(AUTH_LIBS) $(top_builddir)/src/polkit/libpolkit-gobject-1.la

# polkit-agent-helper-1 need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users.
#
install-exec-hook:
	-chown root $(DESTDIR)$(libexecdir)/polkit-agent-helper-1
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-agent-helper-1

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = polkitagentmarshal.list

clean-local :
	rm -f *~

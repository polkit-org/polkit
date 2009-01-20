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


lib_LTLIBRARIES=libpolkit-agent-1.la

libpolkit_agent_1includedir=$(includedir)/polkit-1/polkitagent

libpolkit_agent_1include_HEADERS =                        		\
	polkitagent.h							\
	polkitagenttypes.h						\
	polkitauthenticationsession.h					\
        $(NULL)

libpolkit_agent_1_la_SOURCES =                                   	\
        polkitagent.h							\
	polkitagenttypes.h						\
	polkitauthenticationsession.h	polkitauthenticationsession.c	\
        $(NULL)

libpolkit_agent_1_la_CFLAGS =                                        	\
        -D_POLKIT_AGENT_COMPILATION                                  	\
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
polkit_agent_helper_1_LDADD = $(AUTH_LIBS)

# polkit-agent-helper-1 need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users.
#
install-exec-hook:
	-chown root $(DESTDIR)$(libexecdir)/polkit-agent-helper-1
	-chmod 4755 $(DESTDIR)$(libexecdir)/polkit-agent-helper-1

CLEANFILES = $(BUILT_SOURCES)

clean-local :
	rm -f *~

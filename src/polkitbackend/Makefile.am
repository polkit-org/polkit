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

BUILT_SOURCES =											\
	ckmanager.c					ckmanager.h				\
	cksession.c					cksession.h				\
	ckseat.c					ckseat.h				\
	ckdevice.c					ckdevice.h				\
	ckbindings.c					ckbindings.h				\
	ckbindingsmarshal.list									\
	ckbindingsmarshal.c				ckbindingsmarshal.h			\
	ckbindingstypes.h									\
	ckerror.c					ckerror.h				\
	_polkitagentauthenticationagent.c		_polkitagentauthenticationagent.h	\
	_polkitagentbindings.c				_polkitagentbindings.h			\
	_polkitagentbindingsmarshal.list							\
	_polkitagentbindingsmarshal.c			_polkitagentbindingsmarshal.h		\
	_polkitagentbindingstypes.h								\
	$(NULL)

$(BUILT_SOURCES) : Makefile.am $(top_srcdir)/src/polkitbackend/org.freedesktop.ConsoleKit.xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthenticationAgent.xml
	eggdbus-binding-tool										\
	  --namespace       "Ck"									\
	  --dbus-namespace  "org.freedesktop.ConsoleKit"						\
	  --introspection-xml $(top_srcdir)/src/polkitbackend/org.freedesktop.ConsoleKit.xml		\
	  $(NULL)
	eggdbus-binding-tool										\
	  --namespace       "_PolkitAgent"								\
	  --dbus-namespace  "org.freedesktop.PolicyKit1"						\
	  --introspection-xml $(top_srcdir)/data/org.freedesktop.PolicyKit1.AuthenticationAgent.xml	\
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
	polkitbackendsessionmonitor.h					\
        $(NULL)

libpolkit_backend_1_la_SOURCES =                                   	\
        polkitbackend.h							\
	polkitbackendtypes.h						\
	polkitbackendprivate.h						\
	polkitbackendauthority.h	polkitbackendauthority.c	\
	polkitbackendlocalauthority.h	polkitbackendlocalauthority.c	\
	polkitbackendactionpool.h	polkitbackendactionpool.c	\
	polkitbackendpendingcall.h	polkitbackendpendingcall.c	\
	polkitbackendsessionmonitor.h	polkitbackendsessionmonitor.c	\
	$(BUILT_SOURCES)						\
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

EXTRA_DIST =								\
	org.freedesktop.ConsoleKit.xml					\
	$(NULL)

clean-local :
	rm -f *~

install-exec-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chmod 600 $(DESTDIR)$(localstatedir)/lib/polkit-1

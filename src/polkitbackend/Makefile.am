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

BUILT_SOURCES = 						\
	ck-built-sources.stamp					\
	$(NULL)

ck-built-sources.stamp : Makefile.am $(srcdir)/org.freedesktop.ConsoleKit.xml
	eggdbus-binding-tool										\
	  --namespace       "Ck"									\
	  --dbus-namespace  "org.freedesktop.ConsoleKit"						\
	  --introspection-xml $(top_srcdir)/src/polkitbackend/org.freedesktop.ConsoleKit.xml		\
	  --stamp-file ck-built-sources.stamp								\
	  $(NULL)

# keep in sync with contents of ck-built-sources.stamp (Thanks autotools)
#
ck_built_sources = ckbindingsmarshal.c ckbindingsmarshal.h ckbindingsmarshal.list ckbindings.c ckbindings.h ckbindingstypes.h cksession.c cksession.h docbook-interface-org.freedesktop.ConsoleKit.Session.xml ckseat.c ckseat.h docbook-interface-org.freedesktop.ConsoleKit.Seat.xml ckmanager.c ckmanager.h docbook-interface-org.freedesktop.ConsoleKit.Manager.xml ckerror.c ckerror.h docbook-enum-Error.xml ckdevice.c ckdevice.h docbook-struct-Device.xml

lib_LTLIBRARIES=libpolkit-backend-1.la

libpolkit_backend_1includedir=$(includedir)/polkit-1/polkitbackend

libpolkit_backend_1include_HEADERS =                        		\
	polkitbackend.h							\
	polkitbackendtypes.h						\
	polkitbackendauthority.h					\
	polkitbackendlocalauthority.h					\
	polkitbackendactionpool.h					\
	polkitbackendsessionmonitor.h					\
	polkitbackendconfigsource.h					\
	polkitbackendactionlookup.h					\
        $(NULL)

libpolkit_backend_1_la_SOURCES =                                   	\
	$(ck_built_sources)						\
	$(BUILT_SOURCES)						\
        polkitbackend.h							\
	polkitbackendtypes.h						\
	polkitbackendprivate.h						\
	polkitbackendauthority.h	polkitbackendauthority.c	\
	polkitbackendlocalauthority.h	polkitbackendlocalauthority.c	\
	polkitbackendactionpool.h	polkitbackendactionpool.c	\
	polkitbackendsessionmonitor.h	polkitbackendsessionmonitor.c	\
	polkitbackendconfigsource.h	polkitbackendconfigsource.c	\
	polkitbackendactionlookup.h	polkitbackendactionlookup.c	\
        $(NULL)

libpolkit_backend_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
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

localauthorityconfigdir = $(sysconfdir)/polkit-1/localauthority.conf.d
localauthorityconfig_DATA = 50-localauthority.conf

EXTRA_DIST =								\
	org.freedesktop.ConsoleKit.xml					\
	$(localauthorityconfig_DATA)					\
	$(NULL)

dist-hook :
	(for i in $(ck_built_sources) $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(ck_built_sources) $(BUILT_SOURCES)

install-exec-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1
	-chmod 600 $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(libdir)/polkit-1/extensions

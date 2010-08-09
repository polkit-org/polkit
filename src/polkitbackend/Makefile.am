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

lib_LTLIBRARIES=libpolkit-backend-1.la

libpolkit_backend_1includedir=$(includedir)/polkit-1/polkitbackend

libpolkit_backend_1include_HEADERS =                        		\
	polkitbackend.h							\
	polkitbackendtypes.h						\
	polkitbackendauthority.h					\
	polkitbackendinteractiveauthority.h				\
	polkitbackendlocalauthority.h					\
	polkitbackendactionlookup.h					\
        $(NULL)

libpolkit_backend_1_la_SOURCES =                                   			\
	$(BUILT_SOURCES)								\
        polkitbackend.h									\
	polkitbackendtypes.h								\
	polkitbackendprivate.h								\
	polkitbackendauthority.h		polkitbackendauthority.c		\
	polkitbackendinteractiveauthority.h	polkitbackendinteractiveauthority.c	\
	polkitbackendlocalauthority.h		polkitbackendlocalauthority.c		\
	polkitbackendactionpool.h		polkitbackendactionpool.c		\
	polkitbackendsessionmonitor.h		polkitbackendsessionmonitor.c		\
	polkitbackendconfigsource.h		polkitbackendconfigsource.c		\
	polkitbackendactionlookup.h		polkitbackendactionlookup.c		\
	polkitbackendlocalauthorizationstore.h	polkitbackendlocalauthorizationstore.c	\
        $(NULL)

libpolkit_backend_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
        -D_POLKIT_BACKEND_COMPILATION                                  	\
        $(GLIB_CFLAGS)							\
        $(NULL)

libpolkit_backend_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(EXPAT_LIBS)							\
        $(NULL)

libpolkit_backend_1_la_LDFLAGS = -export-symbols-regex '(^polkit_.*)'

CLEANFILES = $(BUILT_SOURCES)

localauthorityconfigdir = $(sysconfdir)/polkit-1/localauthority.conf.d
localauthorityconfig_DATA = 50-localauthority.conf

EXTRA_DIST =								\
	$(localauthorityconfig_DATA)					\
	$(NULL)

dist-hook :
	(for i in $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(BUILT_SOURCES)

install-exec-hook:
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(localstatedir)/lib/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 700 $(DESTDIR)$(localstatedir)/lib/polkit-1
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1/localauthority/{10-vendor.d,20-org.d,30-site.d,50-local.d,90-mandatory.d}
	-chmod 700 $(DESTDIR)$(sysconfdir)/polkit-1/localauthority
	mkdir -p $(DESTDIR)$(libdir)/polkit-1/extensions

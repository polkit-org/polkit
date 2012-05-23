NULL =

BUILT_SOURCES =

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

noinst_LTLIBRARIES=libpolkit-backend-1.la

initjs.h : init.js
	$(PERL) $(srcdir)/toarray.pl $(srcdir)/init.js init_js > $@

BUILT_SOURCES += initjs.h

libpolkit_backend_1_la_SOURCES =                                   			\
	$(BUILT_SOURCES)								\
        polkitbackend.h									\
	polkitbackendtypes.h								\
	polkitbackendprivate.h								\
	polkitbackendauthority.h		polkitbackendauthority.c		\
	polkitbackendinteractiveauthority.h	polkitbackendinteractiveauthority.c	\
	polkitbackendjsauthority.h		polkitbackendjsauthority.c		\
	polkitbackendactionpool.h		polkitbackendactionpool.c		\
	polkitbackendconfigsource.h		polkitbackendconfigsource.c		\
	polkitbackendactionlookup.h		polkitbackendactionlookup.c		\
        $(NULL)

if HAVE_LIBSYSTEMD_LOGIN
libpolkit_backend_1_la_SOURCES += \
	polkitbackendsessionmonitor.h		polkitbackendsessionmonitor-systemd.c
else
libpolkit_backend_1_la_SOURCES += \
	polkitbackendsessionmonitor.h		polkitbackendsessionmonitor.c
endif

libpolkit_backend_1_la_CFLAGS =                                        	\
        -D_POLKIT_COMPILATION                                  		\
        -D_POLKIT_BACKEND_COMPILATION                                  	\
        $(GLIB_CFLAGS)							\
	$(LIBSYSTEMD_LOGIN_CFLAGS)					\
	$(LIBJS_CFLAGS)							\
        $(NULL)

libpolkit_backend_1_la_LIBADD =                               		\
        $(GLIB_LIBS)							\
	$(LIBSYSTEMD_LOGIN_LIBS)					\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la		\
	$(EXPAT_LIBS)							\
	$(LIBJS_LIBS)							\
        $(NULL)

rulesdir = $(sysconfdir)/polkit-1/rules.d
rules_DATA = 50-default.rules

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST =								\
	init.js								\
	toarray.pl							\
	$(rules_DATA)							\
	$(NULL)

dist-hook :
	(for i in $(BUILT_SOURCES) ; do rm -f $(distdir)/$$i ; done)

clean-local :
	rm -f *~ $(BUILT_SOURCES)

install-exec-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/polkit-1/rules.d
	-chmod 700 $(DESTDIR)$(sysconfdir)/polkit-1/rules.d
	mkdir -p $(DESTDIR)$(datadir)/polkit-1/rules.d
	-chmod 700 $(DESTDIR)$(datadir)/polkit-1/rules.d

## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir)/src -I$(top_srcdir)/src \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	-DPOLKIT_COMPILATION \
	$(DBUS_GLIB_CFLAGS) \
	@GLIB_CFLAGS@

BUILT_SOURCES =						\
	polkit-daemon-backend-glue.h

polkit-daemon-backend-glue.h: org.freedesktop.PolicyKit.Backend.xml Makefile.am
	dbus-binding-tool --prefix=polkit_daemon_backend --mode=glib-server --output=polkit-daemon-backend-glue.h org.freedesktop.PolicyKit.Backend.xml

libexec_PROGRAMS = polkit-backendd

polkit_backendd_SOURCES = 						\
	polkit-daemon-backend.h		polkit-daemon-backend.c		\
	main.c								\
	$(BUILT_SOURCES)

polkit_backendd_CPPFLAGS = 					\
	-I$(top_srcdir)/src					\
	-DG_LOG_DOMAIN=\"polkit_backendd\"			\
	-DDATADIR=\""$(pkgdatadir)"\"				\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"		\
	$(DISABLE_DEPRECATED)					\
	$(AM_CPPFLAGS)

polkit_backendd_LDADD = 				        \
	$(DBUS_GLIB_LIBS) $(top_builddir)/src/polkit/libpolkit-1.la


servicedir       = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.PolicyKit.Backend.service.in
service_DATA     = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	@sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@

dbusconfdir = $(sysconfdir)/dbus-1/system.d
dbusconf_in_files = org.freedesktop.PolicyKit.Backend.conf.in
dbusconf_DATA = $(dbusconf_in_files:.conf.in=.conf)

$(dbusconf_DATA): $(dbusconf_in_files) Makefile
	@sed -e "s|\@polkituser\@|$(POLKIT_USER)|" $< > $@

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = org.freedesktop.PolicyKit.Backend.xml $(service_in_files) $(dbusconf_in_files)

clean-local :
	rm -f *~ $(service_DATA) $(dbusconf_DATA)

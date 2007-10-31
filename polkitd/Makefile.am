## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
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
	polkit-daemon-glue.h

polkit-daemon-glue.h: org.freedesktop.PolicyKit.xml Makefile.am
	dbus-binding-tool --prefix=polkit_daemon --mode=glib-server --output=polkit-daemon-glue.h org.freedesktop.PolicyKit.xml

libexec_PROGRAMS = polkitd

polkitd_SOURCES = 					\
	polkit-daemon.h		polkit-daemon.c		\
	main.c						\
	$(BUILT_SOURCES)

polkitd_CPPFLAGS = 					\
	-I$(top_srcdir)					\
	-DG_LOG_DOMAIN=\"polkitd\"			\
	-DDATADIR=\""$(pkgdatadir)"\"			\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	$(DISABLE_DEPRECATED)				\
	$(AM_CPPFLAGS)

polkitd_LDADD = 				        \
	$(DBUS_GLIB_LIBS) $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la $(top_builddir)/polkit-grant/libpolkit-grant.la


servicedir       = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.PolicyKit.service.in
service_DATA     = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	@sed -e "s|\@polkituser\@|$(POLKIT_USER)|" -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@

dbusconfdir = $(sysconfdir)/dbus-1/system.d
dbusconf_in_files = org.freedesktop.PolicyKit.conf.in
dbusconf_DATA = $(dbusconf_in_files:.conf.in=.conf)

$(dbusconf_DATA): $(dbusconf_in_files) Makefile
	@sed -e "s|\@polkituser\@|$(POLKIT_USER)|" $< > $@

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = org.freedesktop.PolicyKit.xml $(service_in_files) $(dbusconf_in_files)

clean-local :
	rm -f *~ $(service_DATA) $(dbusconf_DATA)

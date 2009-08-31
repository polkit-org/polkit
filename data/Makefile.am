## Process this file with automake to produce Makefile.in

NULL =

servicedir       = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.PolicyKit1.service.in
service_DATA     = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	@sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@

dbusconfdir = $(sysconfdir)/dbus-1/system.d
dbusconf_DATA = org.freedesktop.PolicyKit1.conf

if POLKIT_AUTHFW_PAM
pamdir = $(sysconfdir)/pam.d
pam_DATA = polkit-1
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit-gobject-1.pc polkit-backend-1.pc polkit-agent-1.pc

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = 							\
	org.freedesktop.PolicyKit1.Authority.xml 		\
	org.freedesktop.PolicyKit1.AuthenticationAgent.xml 	\
	$(service_in_files) 					\
	$(dbusconf_DATA) 					\
	$(NULL)


clean-local :
	rm -f *~ $(service_DATA)

## Process this file with automake to produce Makefile.in

servicedir       = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.PolicyKit1.service.in
service_DATA     = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	@sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@

dbusconfdir = $(sysconfdir)/dbus-1/system.d
dbusconf_in_files = org.freedesktop.PolicyKit1.conf.in
dbusconf_DATA = $(dbusconf_in_files:.conf.in=.conf)

$(dbusconf_DATA): $(dbusconf_in_files) Makefile
	@sed -e "s|\@polkituser\@|$(POLKIT_USER)|" $< > $@

if POLKIT_AUTHFW_PAM
pamdir = $(sysconfdir)/pam.d
pam_DATA = polkit-1
endif

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = org.freedesktop.PolicyKit1.Authority.xml $(service_in_files) $(dbusconf_in_files) polkit-1.in

clean-local :
	rm -f *~ $(service_DATA) $(dbusconf_DATA)

## Process this file with automake to produce Makefile.in

NULL =

libprivdir = $(prefix)/lib/polkit-1

# ----------------------------------------------------------------------------------------------------

servicedir       = $(datadir)/dbus-1/system-services
service_in_files = org.freedesktop.PolicyKit1.service.in
service_DATA     = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	@sed -e "s|\@libprivdir\@|$(libprivdir)|" $< > $@

# ----------------------------------------------------------------------------------------------------

dbusconfdir = $(datadir)/dbus-1/system.d
dbusconf_in_files = org.freedesktop.PolicyKit1.conf.in
dbusconf_DATA = $(dbusconf_in_files:.conf.in=.conf)

$(dbusconf_DATA): $(dbusconf_in_files) Makefile
	@sed -e "s|\@polkitd_user\@|$(POLKITD_USER)|" $< > $@

# ----------------------------------------------------------------------------------------------------

if POLKIT_AUTHFW_PAM
pamdir = $(sysconfdir)/pam.d
pam_DATA = polkit-1
endif

# ----------------------------------------------------------------------------------------------------

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit-gobject-1.pc polkit-agent-1.pc

# ----------------------------------------------------------------------------------------------------

systemdservice_in_files = polkit.service.in

if HAVE_SYSTEMD
systemdservicedir       = $(systemdsystemunitdir)
systemdservice_DATA     = $(systemdservice_in_files:.service.in=.service)
$(systemdservice_DATA): $(systemdservice_in_files) Makefile
	@sed -e "s|\@libprivdir\@|$(libprivdir)|" $< > $@
endif

# ----------------------------------------------------------------------------------------------------

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = 							\
	org.freedesktop.PolicyKit1.Authority.xml 		\
	org.freedesktop.PolicyKit1.AuthenticationAgent.xml 	\
	meson.build						\
	$(service_in_files) 					\
	$(dbusconf_in_files) 					\
	$(systemdservice_in_files) 				\
	$(NULL)


clean-local :
	rm -f *~ $(service_DATA) $(dbusconf_DATA) $(systemdservice_DATA)

-include $(top_srcdir)/git.mk

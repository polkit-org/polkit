## Process this file with automake to produce Makefile.in

pamdir = $(sysconfdir)/pam.d
pam_DATA = polkit

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit.pc polkit-dbus.pc polkit-grant.pc

confdir = $(sysconfdir)/PolicyKit
conf_DATA = PolicyKit.conf

dtddir = $(datadir)/PolicyKit
dtd_DATA = config.dtd

DISTCLEANFILES = polkit.pc polkit-dbus.pc polkit-grant.pc PolicyKit.conf

EXTRA_DIST = polkit.in polkit.pc.in polkit-dbus.pc.in polkit-grant.pc.in PolicyKit.conf.in config.dtd

clean-local :
	rm -f *~

PolicyKit.conf: PolicyKit.conf.in Makefile
	$(edit) $< >$@

edit = sed \
	-e 's|@docdir[@]|$(docdir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@datadir[@]|$(datadir)|g'

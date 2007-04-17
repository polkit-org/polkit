## Process this file with automake to produce Makefile.in

pamdir = $(sysconfdir)/pam.d
pam_DATA = polkit

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit.pc polkit-dbus.pc polkit-grant.pc

DISTCLEANFILES = polkit.pc polkit-dbus.pc polkit-grant.pc

EXTRA_DIST = polkit.in polkit.pc.in polkit-dbus.pc.in polkit-grant.pc.in

clean-local :
	rm -f *~

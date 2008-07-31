## Process this file with automake to produce Makefile.in

# See polkit-grant/Makefile.am for discussion
#
if POLKIT_AUTHFW_PAM
pamdir = $(sysconfdir)/pam.d
pam_DATA = polkit-grant-1
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit-1.pc polkit-grant-1.pc

dbusifdir = $(datadir)/dbus-1/interfaces
dbusif_DATA = org.freedesktop.PolicyKit.AuthenticationAgent1.xml

DISTCLEANFILES = polkit-1.pc polkit-grant-1.pc

EXTRA_DIST = polkit-grant-1.in polkit-1.pc.in polkit-grant-1.pc.in org.freedesktop.PolicyKit.AuthenticationAgent1.xml

clean-local :
	rm -f *~

## Process this file with automake to produce Makefile.in

SUBDIRS = libpolkit pam-polkit-console polkitd doc tools privileges

pamdir = $(sysconfdir)/pam.d
pam_DATA = policy-kit

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit.pc

DISTCLEANFILES = polkit.pc

EXTRA_DIST = HACKING polkit-interface-manager.xml polkit-interface-session.xml polkit.pc.in policy-kit.in mkinstalldirs

clean-local :
	rm -f *~

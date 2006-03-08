## Process this file with automake to produce Makefile.in

SUBDIRS = libpolkit doc tools

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit.pc

DISTCLEANFILES = polkit.pc

EXTRA_DIST = HACKING polkit.pc.in mkinstalldirs

clean-local :
	rm -f *~

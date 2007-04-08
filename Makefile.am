## Process this file with automake to produce Makefile.in

SUBDIRS = libpolkit modules doc tools privileges

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libpolkit.pc

DISTCLEANFILES = libpolkit.pc

EXTRA_DIST = HACKING libpolkit.pc.in mkinstalldirs

clean-local :
	rm -f *~

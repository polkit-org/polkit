## Process this file with automake to produce Makefile.in

SUBDIRS = actions data src docs po

NULL =

EXTRA_DIST = 			\
	HACKING 		\
	$(NULL)

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=--disable-man-pages --disable-gtk-doc --disable-introspection

clean-local :
	rm -f *~

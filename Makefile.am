## Process this file with automake to produce Makefile.in

SUBDIRS = actions data src docs po test

NULL =

EXTRA_DIST = 			\
	HACKING 		\
	$(NULL)

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=							\
	--disable-man-pages 							\
	--disable-gtk-doc 							\
	--disable-introspection							\
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)	\
	$(NULL)

sign : dist
	gpg --armor --detach-sign --output polkit-$(VERSION).tar.gz.sign polkit-$(VERSION).tar.gz

publish : sign
	scp polkit-$(VERSION).tar.gz polkit-$(VERSION).tar.gz.sign "david@people.freedesktop.org:/srv/www.freedesktop.org/www/software/polkit/releases/"

publish-docs :
	gtkdoc-rebase --html-dir docs/polkit/html --online
	ssh "david@people.freedesktop.org" "mkdir -p /srv/www.freedesktop.org/www/software/polkit/docs/$(VERSION)"
	scp docs/polkit/html/* "david@people.freedesktop.org:/srv/www.freedesktop.org/www/software/polkit/docs/$(VERSION)"
	ssh "david@people.freedesktop.org" "rm -f /srv/www.freedesktop.org/www/software/polkit/docs/latest; ln -s $(VERSION) /srv/www.freedesktop.org/www/software/polkit/docs/latest"

clean-local :
	rm -f *~

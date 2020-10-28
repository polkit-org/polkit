## Process this file with automake to produce Makefile.in

SUBDIRS = actions data gettext src docs po

if BUILD_TEST
SUBDIRS += test
endif

NULL =

EXTRA_DIST = 			\
	HACKING 		\
	meson.build		\
	meson_options.txt	\
	meson_post_install.py	\
	po/meson.build		\
	$(NULL)

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=							\
	--disable-man-pages 							\
	--disable-introspection							\
	--enable-gtk-doc 							\
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)	\
	$(NULL)

sign : dist
	gpg --armor --detach-sign --output polkit-$(VERSION).tar.gz.sign polkit-$(VERSION).tar.gz

publish : sign
	scp polkit-$(VERSION).tar.gz polkit-$(VERSION).tar.gz.sign "jrybar@people.freedesktop.org:/srv/www.freedesktop.org/www/software/polkit/releases/"

publish-docs :
	gtkdoc-rebase --html-dir docs/polkit/html --online
	ssh "jrybar@people.freedesktop.org" "mkdir -p /srv/www.freedesktop.org/www/software/polkit/docs/$(VERSION)"
	scp docs/polkit/html/* "jrybar@people.freedesktop.org:/srv/www.freedesktop.org/www/software/polkit/docs/$(VERSION)"
	ssh "jrybar@people.freedesktop.org" "rm -f /srv/www.freedesktop.org/www/software/polkit/docs/latest; ln -s $(VERSION) /srv/www.freedesktop.org/www/software/polkit/docs/latest"

clean-local :
	rm -f *~

-include $(top_srcdir)/git.mk

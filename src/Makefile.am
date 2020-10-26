
SUBDIRS = polkit polkitbackend polkitagent programs

if BUILD_EXAMPLES
SUBDIRS += examples
endif

EXTRA_DIST =		\
	meson.build	\
	symbol.map	\
	$(NULL)

clean-local :
	rm -f *~

-include $(top_srcdir)/git.mk


SUBDIRS = . polkit polkitbackend
AM_CFLAGS = $(GLIB_CFLAGS)

check_LTLIBRARIES = libpolkit-test-helper.la
libpolkit_test_helper_la_SOURCES = polkittesthelper.c polkittesthelper.h
libpolkit_test_helper_la_LIBADD = $(GLIB_LIBS)


clean-local :
	rm -f *~

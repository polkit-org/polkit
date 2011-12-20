
SUBDIRS = mocklibc . polkit polkitbackend
AM_CFLAGS = $(GLIB_CFLAGS)

check_LTLIBRARIES = libpolkit-test-helper.la
libpolkit_test_helper_la_SOURCES = polkittesthelper.c polkittesthelper.h
libpolkit_test_helper_la_LIBADD = $(GLIB_LIBS)

EXTRA_DIST = data

# Use mocklibc to override NSS services for tests
export MOCK_PASSWD   := $(abs_top_srcdir)/test/data/etc/passwd
export MOCK_GROUP    := $(abs_top_srcdir)/test/data/etc/group
export MOCK_NETGROUP := $(abs_top_srcdir)/test/data/etc/netgroup
export TESTS_ENVIRONMENT := $(abs_top_builddir)/test/mocklibc/bin/mocklibc

# Include path to mock config files
export POLKIT_TEST_DATA := $(abs_top_srcdir)/test/data


clean-local :
	rm -f *~


# Never install anything in this dir (specifically MockLibc)
install:; @:
install-exec:; @:
install-data:; @:
uninstall:; @:



bin_SCRIPTS = mocklibc

check_SCRIPTS = mocklibc-test
TESTS = mocklibc-test

EXTRA_DIST = mocklibc.in mocklibc-test.in
CLEANFILES = mocklibc mocklibc-test


# Substitute build variables in shell scripts
# See section "4.8.2 Installation Directory Variables" in autoconf manual

edit = sed \
       -e 's|@libdir[@]|$(libdir)|g' \
       -e 's|@libname[@]|$(libname)|g' \
       -e 's|@top_srcdir[@]|$(top_srcdir)|g' \
       -e 's|@top_builddir[@]|$(top_builddir)|g'

mocklibc mocklibc-test: Makefile
	$(edit) $(srcdir)/$@.in > $@
	chmod a+x $@

mocklibc: $(srcdir)/mocklibc.in
mocklibc-test: $(srcdir)/mocklibc-test.in

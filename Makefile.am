## Process this file with automake to produce Makefile.in

SUBDIRS = data src polkit-backendd doc tools policy po test

# Creating ChangeLog from git log (taken from cairo/Makefile.am):
ChangeLog: $(srcdir)/ChangeLog

$(srcdir)/ChangeLog:
	@if test -d "$(srcdir)/.git"; then \
	  (cd "$(srcdir)" && \
	  ./missing --run git-log --stat) | fmt --split-only > $@.tmp \
	  && mv -f $@.tmp $@ \
	  || ($(RM) $@.tmp; \
	      echo Failed to generate ChangeLog, your ChangeLog may be outdated >&2; \
	      (test -f $@ || echo git-log is required to generate this file >> $@)); \
	else \
	  test -f $@ || \
	  (echo A git checkout and git-log is required to generate ChangeLog >&2 && \
	  echo A git checkout and git-log is required to generate this file >> $@); \
	fi

if POLKIT_GCOV_ENABLED
.PHONY: ChangeLog $(srcdir)/ChangeLog coverage-report.txt
coverage-report.txt :
	make -C src/kit coverage-report.txt
	make -C src/polkit coverage-report.txt
	make -C src/polkit-dbus coverage-report.txt
	make -C src/polkit-grant coverage-report.txt
	$(top_srcdir)/test/create-coverage-report.sh "PolicyKit" `cat src/kit/covered-files.txt src/polkit/covered-files.txt src/polkit-dbus/covered-files.txt src/polkit-grant/covered-files.txt` > coverage-report.txt

check-coverage: coverage-report.txt
	cat coverage-report.txt
else
.PHONY: ChangeLog $(srcdir)/ChangeLog

coverage-report.txt:
	@echo "Need to reconfigure with --enable-gcov"

check-coverage:
	@echo "Need to reconfigure with --enable-gcov"
endif

if POLKIT_BUILD_TESTS
install:
	@echo "Cowardly refusing to install with --enable-tests."
	@exit 1
endif

EXTRA_DIST = 			\
	HACKING 		\
	mkinstalldirs 		\
	ChangeLog 		\
	intltool-extract.in 	\
	intltool-merge.in 	\
	intltool-update.in

DISTCLEANFILES = \
	intltool-extract	\
	intltool-merge		\
	intltool-update

# xsltproc barfs on 'make distcheck'; disable for now
DISTCHECK_CONFIGURE_FLAGS=--disable-man-pages --disable-gtk-doc

clean-local :
	rm -f *~

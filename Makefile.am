## Process this file with automake to produce Makefile.in

SUBDIRS = libpolkit pam-polkit-console polkitd doc tools privileges

pamdir = $(sysconfdir)/pam.d
pam_DATA = policy-kit

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = polkit.pc

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

.PHONY: ChangeLog $(srcdir)/ChangeLog

DISTCLEANFILES = polkit.pc

EXTRA_DIST = HACKING polkit-interface-manager.xml polkit-interface-session.xml polkit.pc.in policy-kit.in mkinstalldirs ChangeLog

clean-local :
	rm -f *~

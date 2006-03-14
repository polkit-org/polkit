
INCLUDES = \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	-DPACKAGE_LOCALSTATEDIR=\""$(localstatedir)"\" \
	-I$(top_srcdir) \
	@GLIB_CFLAGS@ \
	@DBUS_GLIB_CFLAGS@

# polkitd
#

sbin_PROGRAMS = polkitd

polkitd_SOURCES =                  					\
	polkit-marshal.c                polkit-marshal.h                \
	polkit-session.c 		polkit-session.h		\
	polkit-manager.c 		polkit-manager.h		\
					polkit-interface-manager-glue.h \
					polkit-interface-session-glue.h \
	policy.c                        policy.h                        \
	main.c

polkitd_CFLAGS = -fno-strict-aliasing
polkitd_LDADD = @GLIB_LIBS@ @DBUS_GLIB_LIBS@ @AUTH_LIBS@

#### Init scripts fun
SCRIPT_IN_FILES=PolicyKit.in

## Red Hat start
if OS_TYPE_RED_HAT

initddir=$(sysconfdir)/rc.d/init.d

initd_SCRIPTS= 	\
	PolicyKit

endif
## Red Hat end

# D-BUS configuration file
#

dbusdir = $(sysconfdir)/dbus-1/system.d
dist_dbus_DATA = PolicyKit.conf

# D-BUS glue
#

polkit-interface-manager-glue.h: ../polkit-interface-manager.xml Makefile.am
	dbus-binding-tool --prefix=polkit_manager --mode=glib-server --output=polkit-interface-manager-glue.h ../polkit-interface-manager.xml

polkit-interface-session-glue.h: ../polkit-interface-session.xml Makefile.am
	dbus-binding-tool --prefix=polkit_session --mode=glib-server --output=polkit-interface-session-glue.h ../polkit-interface-session.xml

BUILT_SOURCES = polkit-interface-manager-glue.h polkit-interface-session-glue.h

# Marshallers
#

polkit-marshal.c: Makefile polkit-marshal.list
	glib-genmarshal --prefix=polkit_marshal $(srcdir)/polkit-marshal.list --header --body > $@.tmp && mv $@.tmp $@

polkit-marshal.h: Makefile polkit-marshal.list
	glib-genmarshal --prefix=polkit_marshal $(srcdir)/polkit-marshal.list --header > $@.tmp && mv $@.tmp $@

BUILT_SOURCES += polkit-marshal.c polkit-marshal.h


# Test harness 
#

check_PROGRAMS = polkitd-test

polkitd_test_SOURCES =                             \
	policy.c		policy.h	   \
	polkitd-test.c

polkitd_test_LDADD = @GLIB_LIBS@

TESTS = polkitd-test



EXTRA_DIST = polkit-marshal.list

# Clean
#

clean-local:
	rm -f *~ $(BUILT_SOURCES) PolicyKit.conf

## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_builddir) -I$(top_srcdir) \
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\" \
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_BIN_DIR=\""$(bindir)"\" \
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_LIB_DIR=\""$(libdir)"\" \
	-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT	\
	-DPOLKIT_COMPILATION \
	@GLIB_CFLAGS@ @DBUS_CFLAGS@

lib_LTLIBRARIES=libpolkit-grant.la

libpolkit_grantincludedir=$(includedir)/PolicyKit/polkit-grant

libpolkit_grantinclude_HEADERS =              				\
	polkit-grant.h

libpolkit_grant_la_SOURCES =      					\
	polkit-grant.h		polkit-grant.c


if POLKIT_AUTHDB_DUMMY
libpolkit_grant_la_SOURCES += polkit-authorization-db-dummy-write.c
endif

if POLKIT_AUTHDB_DEFAULT
libpolkit_grant_la_SOURCES += polkit-authorization-db-write.c
endif

libpolkit_grant_la_LIBADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la

libpolkit_grant_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

# Only if the authdb backend has the capability POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN
# then the backend must supply the /usr/libexec/polkit-grant-helper program.. also remember to
# adjust the PAM stuff in data/Makefile.am
#
if POLKIT_AUTHDB_DEFAULT
libexec_PROGRAMS = polkit-grant-helper polkit-grant-helper-pam polkit-explicit-grant-helper polkit-revoke-helper 

polkit_grant_helper_SOURCES = polkit-grant-helper.c
polkit_grant_helper_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la $(top_builddir)/polkit-grant/libpolkit-grant.la

polkit_grant_helper_pam_SOURCES = polkit-grant-helper-pam.c
polkit_grant_helper_pam_LDADD = @AUTH_LIBS@

polkit_explicit_grant_helper_SOURCES = polkit-explicit-grant-helper.c
polkit_explicit_grant_helper_CFLAGS = @DBUS_CFLAGS@
polkit_explicit_grant_helper_LDADD = $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

polkit_revoke_helper_SOURCES = polkit-revoke-helper.c
polkit_revoke_helper_CFLAGS = @DBUS_CFLAGS@
polkit_revoke_helper_LDADD = $(top_builddir)/polkit/libpolkit.la $(top_builddir)/polkit-dbus/libpolkit-dbus.la

# polkit-grant-helper needs to be setgid polkituser to be able to
# write cookies to /var/lib/PolicyKit and /var/run/PolicyKit
#
# polkit-grant-helper-pam need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users. As only polkit-grant-helper will invoke it
# we make it owned by the polkitiuser group and non-readable / 
# non-executable to the world
#
# polkit-explicit-grant-helper needs to be setgid $POLKIT_GROUP to be
# able to edit authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
# polkit-revoke-helper needs to be setgid $POLKIT_GROUP to be able to
# edit authorization files in /var/lib/PolicyKit and
# /var/run/PolicyKit
#
install-exec-hook:
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-grant-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-grant-helper
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-grant-helper-pam
	-chmod 4750 $(DESTDIR)$(libexecdir)/polkit-grant-helper-pam
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-explicit-grant-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-explicit-grant-helper
	-chgrp $(POLKIT_GROUP) $(DESTDIR)$(libexecdir)/polkit-revoke-helper
	-chmod 2755 $(DESTDIR)$(libexecdir)/polkit-revoke-helper
endif

clean-local :
	rm -f *~ $(BUILT_SOURCES)

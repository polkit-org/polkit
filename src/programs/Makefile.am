
NULL =

INCLUDES =                                              	\
	-I$(top_builddir)/src                           	\
	-I$(top_srcdir)/src                             	\
	-DPACKAGE_LIBEXEC_DIR=\""$(libexecdir)"\"       	\
	-DPACKAGE_SYSCONF_DIR=\""$(sysconfdir)"\"       	\
	-DPACKAGE_DATA_DIR=\""$(datadir)"\"             	\
	-DPACKAGE_BIN_DIR=\""$(bindir)"\"               	\
	-DPACKAGE_LOCALSTATE_DIR=\""$(localstatedir)"\" 	\
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\"         	\
	-DPACKAGE_LIB_DIR=\""$(libdir)"\"               	\
	-D_POSIX_PTHREAD_SEMANTICS                      	\
	-D_REENTRANT	                                	\
	$(NULL)

bin_PROGRAMS = polkit-verify-claim-1

polkit_verify_claim_1_SOURCES = polkit-verify-claim.c

polkit_verify_claim_1_CFLAGS =                             	\
	$(GLIB_CFLAGS)						\
	$(GIO_CFLAGS)						\
	$(DBUS_GLIB_CFLAGS)					\
	$(NULL)

polkit_verify_claim_1_LDADD =  	                      		\
	$(GLIB_LDADD)						\
	$(GIO_LDADD)						\
	$(DBUS_GLIB_LDADD)					\
	$(top_builddir)/src/polkit/libpolkit-gobject-1.la	\
	$(NULL)

clean-local :
	rm -f *~

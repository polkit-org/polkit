
LOCKDIR     = $(localstatedir)/run/polkit-console
LOCKDIRMODE = 0700

securelibdir = $(PAM_MODULE_DIR)
securelib_LTLIBRARIES = pam_polkit_console.la

pam_polkit_console_la_LDFLAGS = -no-undefined -avoid-version -module
pam_polkit_console_la_LIBADD = -lpam
pam_polkit_console_la_CFLAGS = -DLOCKDIR=\"$(LOCKDIR)\"

pam_polkit_console_la_SOURCES = pam-polkit-console.c

clean-local :
	rm -f *~

install-data-local:
	mkdir -m $(LOCKDIRMODE) -p $(DESTDIR)$(LOCKDIR)

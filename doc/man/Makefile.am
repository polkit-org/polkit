
if MAN_PAGES_ENABLED

MAN_IN_FILES = polkit-check-caller.1.in polkit-check-session.1.in polkit-privilege-file-validate.1.in PolicyKit.8.in polkit-module-default.8.in polkit-module-allow-all.8.in polkit-module-deny-all.8.in polkit-module-run-program.8.in polkit-module-builtins.8.in

man_MANS = $(MAN_IN_FILES:.in=)

endif # MAN_PAGES_ENABLED

EXTRA_DIST=$(man_MANS) $(MAN_IN_FILES)

clean-local:
	rm -f *~ *.1 *.8

%: %.in Makefile
	$(edit) $< >$@

edit = sed \
	-e 's|@docdir[@]|$(docdir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'


if MAN_PAGES_ENABLED

MAN_IN_FILES = polkit-check-caller.1.in polkit-check-session.1.in

man_MANS = $(MAN_IN_FILES:.in=)

endif # MAN_PAGES_ENABLED

EXTRA_DIST=$(man_MANS) $(MAN_IN_FILES)

clean-local:
	rm -f *~ *.1

%: %.in Makefile
	$(edit) $< >$@

edit = sed \
	-e 's|@docdir[@]|$(docdir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g'

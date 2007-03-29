
if MAN_PAGES_ENABLED

MAN_IN_FILES = polkit-check-caller.1.in polkit-check-session.1.in

man_MANS = polkit-check-caller.1 polkit-check-session.1

endif # MAN_PAGES_ENABLED

EXTRA_DIST=$(man_MANS) $(MAN_IN_FILES)

clean-local:
	rm -f *~

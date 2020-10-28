
polkit_actiondir = $(datadir)/polkit-1/actions
polkit_action_in_files = org.freedesktop.policykit.policy.in
dist_polkit_action_DATA = $(polkit_action_in_files:.policy.in=.policy)

org.freedesktop.policykit.policy: org.freedesktop.policykit.policy.in
	$(AM_V_GEN) GETTEXTDATADIR=$(top_srcdir)/gettext $(MSGFMT) --xml --template $< -d $(top_srcdir)/po -o $@

#check:
#	$(top_builddir)/tools/polkit-policy-file-validate-1 $(top_srcdir)/policy/$(dist_polkit_action_DATA)

clean-local :
	rm -f *~

DISTCLEANFILES = org.freedesktop.policykit.policy

EXTRA_DIST =					\
	org.freedesktop.policykit.policy.in	\
	meson.build				\
	$(NULL)

-include $(top_srcdir)/git.mk


polkit_actiondir = $(datadir)/polkit-1/actions

dist_polkit_action_DATA = org.freedesktop.policykit.policy

@INTLTOOL_POLICY_RULE@

#check:
#	$(top_builddir)/tools/polkit-policy-file-validate-1 $(top_srcdir)/policy/$(dist_polkit_action_DATA)

clean-local :
	rm -f *~

DISTCLEANFILES = org.freedesktop.policykit.policy

EXTRA_DIST = org.freedesktop.policykit.policy.in


polkit_policydir = $(datadir)/PolicyKit/policy

dist_polkit_policy_DATA = org.freedesktop.policykit.policy

@INTLTOOL_POLICY_RULE@

check:
	$(top_builddir)/tools/polkit-policy-file-validate $(dist_polkit_policy_DATA)

clean-local :
	rm -f *~

DISTCLEANFILES = org.freedesktop.policykit.policy

EXTRA_DIST = org.freedesktop.policykit.policy.in

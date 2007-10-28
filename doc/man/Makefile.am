
if MAN_PAGES_ENABLED

man_MANS = polkit-auth.1 	         \
	   polkit-action.1 		 \
	   polkit-config-file-validate.1 \
	   polkit-policy-file-validate.1 \
	   PolicyKit.conf.5		 \
	   PolicyKit.8

%.1 %.5 %.8 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif # MAN_PAGES_ENABLED

EXTRA_DIST= PolicyKit.conf.xml              \
	    PolicyKit.xml                   \
	    polkit-config-file-validate.xml \
	    polkit-auth.xml	            \
	    polkit-action.xml               \
	    polkit-policy-file-validate.xml

clean-local:
	rm -f *~ *.1 *.5 *.8


if MAN_PAGES_ENABLED

man_MANS = polkit-auth-1.1 	           \
	   polkit-action-1.1 		   \
	   polkit-policy-file-validate-1.1 \
	   PolicyKit-1.8

%-1.1 %-1.8 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif # MAN_PAGES_ENABLED

EXTRA_DIST= PolicyKit.xml                   	\
	    polkit-auth.xml	            	\
	    polkit-action.xml             	\
	    polkit-policy-file-validate.xml

clean-local:
	rm -f *~ *.1 *.5 *.8


NULL =

if MAN_PAGES_ENABLED

man_MANS = 				\
	PolicyKit-1.8			\
	polkit-1.1			\
	$(NULL)

%-1.8 %-1.1 : %.xml
	$(XSLTPROC) -nonet http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif # MAN_PAGES_ENABLED

EXTRA_DIST = 				\
	PolicyKit.xml                   \
	polkit.xml			\
	$(NULL)

clean-local:
	rm -f *~ *.1 *.8

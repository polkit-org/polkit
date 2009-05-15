
NULL =

if MAN_PAGES_ENABLED

man_MANS = 				\
	PolicyKit-1.8			\
	polkit-1.1			\
	pkexec.1			\
	$(NULL)

%-1.8 %-1.1 : %.xml
	$(XSLTPROC) -nonet --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

pkexec.1 : pkexec.xml
	$(XSLTPROC) -nonet --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif # MAN_PAGES_ENABLED

EXTRA_DIST = 				\
	PolicyKit.xml                   \
	polkit.xml			\
	pkexec.xml			\
	$(NULL)

clean-local:
	rm -f *~ *.1 *.8

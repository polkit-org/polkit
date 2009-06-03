
NULL =

if MAN_PAGES_ENABLED

man_MANS = 				\
	PolicyKit-1.8			\
	polkitd-1.8			\
	pkexec.1			\
	pkcheck.1			\
	pkaction.1			\
	$(NULL)

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif # MAN_PAGES_ENABLED

EXTRA_DIST = 				\
	PolicyKit-1.xml                 \
	pkexec.xml			\
	pkcheck.xml			\
	pkaction.xml			\
	$(NULL)

clean-local:
	rm -f *~ *.1 *.8

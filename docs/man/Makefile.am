
NULL =

if MAN_PAGES_ENABLED

man_MANS = 				\
	polkit.8			\
	polkitd.8			\
	pklocalauthority.8		\
	pkexec.1			\
	pkcheck.1			\
	pkaction.1			\
	pkttyagent.1			\
	$(NULL)

%.8 %.1 : %.xml
	$(XSLTPROC) -nonet --stringparam man.base.url.for.relative.links $(datadir)/gtk-doc/html/polkit-1/ --xinclude http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

endif # MAN_PAGES_ENABLED

EXTRA_DIST = 				\
	polkit.xml                 	\
	polkitd.xml			\
	pklocalauthority.xml		\
	pkexec.xml			\
	pkcheck.xml			\
	pkaction.xml			\
	pkttyagent.xml			\
	$(NULL)

clean-local:
	rm -f *~ *.1 *.8

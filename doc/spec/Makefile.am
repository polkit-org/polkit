
FIGURE_FILES =

SPEC_XML_EXTRA_FILES =			\
	polkit-spec-introduction.xml

if DOCBOOK_DOCS_ENABLED

htmldocdir = $(docdir)/spec
htmldoc_DATA = polkit-spec.html $(FIGURE_FILES) docbook.css

polkit-spec.html : polkit-spec.xml.in $(FIGURE_FILES) $(SPEC_XML_EXTRA_FILES)
	${XMLLINT} --xinclude polkit-spec.xml.in > polkit-spec.xml
	$(XMLTO) html-nochunks -m config.xsl polkit-spec.xml

endif # DOCBOOK_DOCS_ENABLED

clean-local:
	rm -f *~
	rm -f *.html
	rm -f polkit-spec.xml

EXTRA_DIST =				\
	polkit-spec.xml.in		\
	config.xsl			\
	docbook.css			\
	$(SPEC_XML_EXTRA_FILES)		\
	$(FIGURE_FILES)

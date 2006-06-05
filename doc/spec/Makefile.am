

FIGURE_FILES =                        	\
	polkit-arch.png

if DOCBOOK_DOCS_ENABLED

htmldocdir = $(DOCDIR)/spec
htmldoc_DATA = polkit-spec.html $(FIGURE_FILES)

polkit-spec.html : polkit-spec.xml $(FIGURE_FILES)
	$(XMLTO) html-nochunks polkit-spec.xml

clean-local:
	rm -f *~
	rm -f polkit-spec.html polkit-spec.xml


endif # DOCBOOK_DOCS_ENABLED

EXTRA_DIST = polkit-spec.html    \
	     polkit-spec.xml.in  \
	     polkit-arch.dia	 \
	     $(FIGURE_FILES)

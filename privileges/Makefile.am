
polkit_privilegedir = $(sysconfdir)/PolicyKit/privileges

dist_polkit_privilege_DATA =

check:
	for f in $(dist_polkit_privilege_DATA); do \
          echo "Validating privilege file: $$f"; \
          $(top_builddir)/tools/polkit-privilege-file-validate --file $(srcdir)/$$f; \
          if [ "$$?" != "0" ]; then \
            echo "failed"; \
            exit 1; \
          fi; \
        done

clean-local :
	rm -f *~

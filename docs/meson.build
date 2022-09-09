pk_api_docpath = pk_prefix / gnome.gtkdoc_html_dir(pk_api_name)

enable_man = get_option('man')
if enable_man
  subdir('man')
endif

enable_gtk_doc = get_option('gtk_doc')
if enable_gtk_doc
  content_files += configure_file(
    input: 'extensiondir.xml.in',
    output: '@BASENAME@',
    configuration: {'libdir': pk_prefix / pk_libdir},
  )

  content_files += configure_file(
    input: 'version.xml.in',
    output: '@BASENAME@',
    configuration: {'VERSION': pk_version},
  )

  subdir('polkit')
endif

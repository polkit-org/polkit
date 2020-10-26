doc_module = pk_api_name

src_dirs = [
  source_root / 'src/polkit',
  source_root / 'src/polkitagent',
]

private_headers = [
  'polkitagenthelperprivate.h',
  'polkitprivate.h',
]

content_files += files(
  'docbook-interface-org.freedesktop.PolicyKit1.AuthenticationAgent.xml',
  'docbook-interface-org.freedesktop.PolicyKit1.Authority.xml',
)

gnome.gtkdoc(
  doc_module,
  main_xml: doc_module + '-docs.xml',
  src_dir: src_dirs,
  ignore_headers: private_headers,
  dependencies: libpolkit_agent_dep,
  namespace: meson.project_name(),
  html_assets: html_images,
  fixxref_args: '--html-dir=' + pk_api_docpath,
  gobject_typesfile: files(doc_module + '.types'),
  content_files: content_files,
  install: true,
)

policy = 'org.freedesktop.policykit.examples.pkexec.policy'

i18n.merge_file(
  input: policy + '.in',
  output: '@BASENAME@',
  po_dir: po_dir,
  data_dirs: its_dir,
  install: true,
  install_dir: pk_pkgactiondir,
)

program = 'cancel'

executable(
  program,
  program + '.c',
  include_directories: top_inc,
  dependencies: libpolkit_gobject_dep,
)

executable(
  'pk-example-frobnicate',
  'frobnicate.c',
  include_directories: top_inc,
  dependencies: glib_dep,
  install: true,
)

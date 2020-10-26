policy = 'org.freedesktop.policykit.examples.pkexec.policy'

custom_target(
  policy,
  input: policy + '.in',
  output: '@BASENAME@',
  command: intltool_xml_cmd,
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

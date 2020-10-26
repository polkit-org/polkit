policy = 'org.freedesktop.policykit.policy'

custom_target(
  policy,
  input: policy + '.in',
  output: '@BASENAME@',
  command: intltool_xml_cmd,
  install: true,
  install_dir: pk_pkgactiondir,
)

policy = 'org.freedesktop.policykit.policy'

policy_file = i18n.merge_file(
  input: policy + '.in',
  output: '@BASENAME@',
  po_dir: po_dir,
  data_dirs: its_dir,
  install: true,
  install_dir: pk_pkgactiondir,
)

xmllint = find_program('xmllint', required: false)
if xmllint.found()
  test(
    'validate-actions', xmllint,
    env: {
      'XML_CATALOG_FILES': catalog_xml_uninstalled.full_path(),
    },
    args: [
      '--nonet', '--noblanks', '--noout', '--valid',
      policy_file,
    ],
  )
endif

service_conf = {
  'libprivdir': pk_prefix / pk_libprivdir,
  'polkitd_user': polkitd_user,
  'polkitd_uid': polkitd_uid,
}

configure_file(
  input: 'org.freedesktop.PolicyKit1.service.in',
  output: '@BASENAME@',
  configuration: service_conf,
  install: true,
  install_dir: dbus_system_bus_services_dir,
)

configure_file(
  input: 'org.freedesktop.PolicyKit1.conf.in',
  output: '@BASENAME@',
  configuration: {'polkitd_user': polkitd_user},
  install: true,
  install_dir: dbus_policydir,
)

if enable_pam
  if os_type == 'debian' and pam_include == ''
    install_data(
      'polkit-1.debian',
      rename: 'polkit-1',
      install_dir: pam_prefix
    )
  else
    configure_file(
      input: 'polkit-1.in',
      output: '@BASENAME@',
      configuration: pam_conf,
      install: true,
      install_dir: pam_prefix,
    )
  endif
endif

if not get_option('libs-only')
  configure_file(
    input: 'polkit.service.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: systemdsystemunitdir,
  )

  configure_file(
    input: 'polkit-agent-helper@.service.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: systemdsystemunitdir,
  )

  install_data(
    'polkit-agent-helper.socket',
    install_dir: systemdsystemunitdir,
  )

  configure_file(
    input: 'polkit.conf.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: sysusers_dir,
  )

  xml_dir = pk_datadir / 'xml' / 'polkit-1'
  install_data(
    'policyconfig-1.dtd',
    install_dir: xml_dir,
  )

  configure_file(
    input: 'catalog.xml.in',
    output: 'catalog.xml',
    install_dir: xml_dir,
    configuration: {'POLKIT_DTD_DIR': get_option('prefix') / xml_dir},
  )

  configure_file(
    input: 'polkit-tmpfiles.conf.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: tmpfiles_dir,
  )
endif

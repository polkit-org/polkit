if activated_helper == 'true'
  # Comment out polkit-agent-helper.socket's Install section
  helper_install = '#'
else
  helper_install = ''
endif

service_conf = {
  'libprivdir': pk_prefix / pk_libprivdir,
  'polkitd_user': polkitd_user,
  'polkitd_uid': polkitd_uid,
  'polkitd_gid': polkitd_gid,
  'helper_install': helper_install,
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

  configure_file(
    input: 'polkit-agent-helper.socket.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: systemdsystemunitdir,
  )

  if activated_helper == 'true'
    install_symlink(
      'polkit-agent-helper.socket',
      install_dir: systemdsystemunitdir / 'sockets.target.wants',
      pointing_to: '../polkit-agent-helper.socket',
    )
  endif

  if polkitd_gid != '-'
    sysusers_template = 'polkit.conf.in-with-gid'
  else
    sysusers_template = 'polkit.conf.in'
  endif

  configure_file(
    input: sysusers_template,
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: sysusers_dir,
  )

  install_data(
    'policyconfig-1.dtd',
    install_dir: pk_datadir / 'polkit-1'
  )

  install_data(
    'polkitd.conf',
    install_dir: pk_datadir / 'polkit-1'
  )

  configure_file(
    input: 'polkit-tmpfiles.conf.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: tmpfiles_dir,
  )
endif

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
  configure_file(
    input: 'polkit-1.in',
    output: '@BASENAME@',
    configuration: pam_conf,
    install: true,
    install_dir: pam_prefix,
  )
endif

configure_file(
  input: 'polkit.service.in',
  output: '@BASENAME@',
  configuration: service_conf,
  install: true,
  install_dir: systemdsystemunitdir,
)

configure_file(
  input: 'polkit.conf.in',
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
  'polkit-tmpfiles.conf',
  install_dir: tmpfiles_dir
)

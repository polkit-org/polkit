service_conf = {'libprivdir': pk_prefix / pk_libprivdir}

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
    install_dir: pk_sysconfdir / 'pam.d',
  )
endif

if enable_logind
  configure_file(
    input: 'polkit.service.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: systemd_systemdsystemunitdir,
  )
endif

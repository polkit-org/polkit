service_conf = {'libprivdir': pk_prefix / pk_pkglibdir}

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

its_data = files(
  'polkit.its',
  'polkit.loc',
)

install_data(
  its_data,
  install_dir: pk_datadir / 'gettext/its',
)

if enable_logind
  configure_file(
    input: 'polkit.service.in',
    output: '@BASENAME@',
    configuration: service_conf,
    install: true,
    install_dir: systemd_systemdsystemunitdir,
  )
endif

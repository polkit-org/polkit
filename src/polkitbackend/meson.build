name = '@0@-backend-@1@'.format(meson.project_name(), pk_api_version)

sources = files(
  'polkitbackendactionlookup.c',
  'polkitbackendactionpool.c',
  'polkitbackendauthority.c',
  'polkitbackendinteractiveauthority.c',
  'polkitbackendjsauthority.cpp',
)

output = 'initjs.h'

sources += custom_target(
  output,
  input: 'init.js',
  output: output,
  capture: true,
  command: [find_program('perl'), meson.current_source_dir() / 'toarray.pl', '@INPUT@', 'init_js'],
)

deps = [
  expat_dep,
  libpolkit_gobject_dep,
  mozjs_dep,
]

c_flags = [
  '-D_POLKIT_COMPILATION',
  '-D_POLKIT_BACKEND_COMPILATION',
  '-DPACKAGE_DATA_DIR="@0@"'.format(pk_prefix / pk_datadir),
  '-DPACKAGE_SYSCONF_DIR="@0@"'.format(pk_prefix / pk_sysconfdir),
]

if enable_logind
  sources += files('polkitbackendsessionmonitor-systemd.c')

  deps += logind_dep
else
  sources += files('polkitbackendsessionmonitor.c')
endif

libpolkit_backend = static_library(
  name,
  sources: sources,
  include_directories: top_inc,
  dependencies: deps,
  c_args: c_flags,
  cpp_args: c_flags,
)

install_data(
  '50-default.rules',
  install_dir: pk_pkgsysconfdir / 'rules.d',
)

program = 'polkitd'

c_flags = [
  '-DG_LOG_DOMAIN="@0@-@1@"'.format(program, pk_api_version),
  '-DPOLKIT_BACKEND_I_KNOW_API_IS_SUBJECT_TO_CHANGE',
]

executable(
  program,
  program + '.c',
  include_directories: top_inc,
  dependencies: libpolkit_gobject_dep,
  c_args: c_flags,
  link_with: libpolkit_backend,
  install: true,
  install_dir: pk_libprivdir,
)

name = '@0@-agent-@1@'.format(meson.project_name(), pk_api_version)

enum_headers = files('polkitagentlistener.h')

headers = enum_headers + files(
  'polkitagent.h',
  'polkitagentsession.h',
  'polkitagenttextlistener.h',
  'polkitagenttypes.h',
)

install_headers(
  headers,
  install_dir: pk_pkgincludedir / 'polkitagent',
)

enum_sources = gnome.mkenums_simple(
  'polkitagentenumtypes',
  sources: enum_headers,
  install_header: true,
  install_dir: pk_pkgincludedir / 'polkitagent',
)

marshal = 'polkitagentmarshal'

marshal_sources = gnome.genmarshal(
  marshal,
  sources: marshal + '.list',
  prefix: '_polkit_agent_marshal',
)

sources = enum_sources + marshal_sources + files(
  'polkitagentlistener.c',
  'polkitagentsession.c',
  'polkitagenttextlistener.c',
)

deps = [
  expat_dep,
  gio_unix_dep,
  libpolkit_gobject_dep,
]

c_flags = [
  '-D_POLKIT_COMPILATION',
  '-D_POLKIT_AGENT_COMPILATION',
  '-DPACKAGE_PREFIX="@0@"'.format(pk_prefix),
]

libpolkit_agent = shared_library(
  name,
  sources: sources,
  version: libversion,
  include_directories: top_inc,
  dependencies: deps,
  c_args: c_flags,
  link_args: ldflags,
  link_depends: symbol_map,
  install: true,
)

libpolkit_agent_dep = declare_dependency(
  sources: enum_sources[1],
  include_directories: '.',
  dependencies: libpolkit_gobject_dep,
  link_with: libpolkit_agent,
)

pkg.generate(
  libraries: libpolkit_agent,
  version: pk_version,
  name: name,
  description: 'PolicyKit Authentication Agent API',
  filebase: name,
  subdirs: pk_api_name,
  requires: 'polkit-gobject-1',
  variables: 'exec_prefix=${prefix}',
)

if enable_introspection
  incs = [
    'Gio-2.0',
    libpolkit_gobject_gir[0],
  ]

  c_flags = [
    '-D_POLKIT_AGENT_COMPILATION',
    '-D_POLKIT_COMPILATION',
  ]

  gnome.generate_gir(
    libpolkit_agent,
    sources: sources + headers,
    includes: incs,
    extra_args: c_flags,
    nsversion: pk_gir_version,
    namespace: 'PolkitAgent',
    export_packages: name,
    header: 'polkitagent/polkitagent.h',
    install: true,
  )
endif

sources = files(
  'polkitagenthelperprivate.c',
  'polkitagenthelper-@0@.c'.format(auth_fw),
)

deps = auth_deps + [libpolkit_gobject_dep]

executable(
  '@0@-agent-helper-@1@'.format(meson.project_name(), pk_api_version),
  sources,
  include_directories: top_inc,
  dependencies: deps,
  c_args: '-D_POLKIT_COMPILATION',
  install: true,
  install_dir: pk_libprivdir,
)

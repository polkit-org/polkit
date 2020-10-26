name = '@0@-gobject-@1@'.format(meson.project_name(), pk_api_version)

enum_headers = files(
  'polkitauthorityfeatures.h',
  'polkitcheckauthorizationflags.h',
  'polkiterror.h',
  'polkitimplicitauthorization.h',
)

headers = enum_headers + files(
  'polkitactiondescription.h',
  'polkitauthority.h',
  'polkitauthorizationresult.h',
  'polkitdetails.h',
  'polkit.h',
  'polkitidentity.h',
  'polkitpermission.h',
  'polkitsubject.h',
  'polkitsystembusname.h',
  'polkittemporaryauthorization.h',
  'polkitunixgroup.h',
  'polkitunixnetgroup.h',
  'polkitunixprocess.h',
  'polkitunixsession.h',
  'polkitunixuser.h',
)

private_headers = files(
  'polkitprivate.h',
  'polkittypes.h',
)

install_headers(
  headers + private_headers,
  install_dir: pk_pkgincludedir / 'polkit',
)

common_deps = [
  gio_dep,
  glib_dep,
]

enum_sources = gnome.mkenums_simple(
  'polkitenumtypes',
  sources: enum_headers,
  install_header: true,
  install_dir: pk_pkgincludedir / 'polkit',
)

sources = enum_sources + files(
  'polkitactiondescription.c',
  'polkitauthority.c',
  'polkitauthorityfeatures.c',
  'polkitauthorizationresult.c',
  'polkitcheckauthorizationflags.c',
  'polkitdetails.c',
  'polkiterror.c',
  'polkitidentity.c',
  'polkitimplicitauthorization.c',
  'polkitpermission.c',
  'polkitsubject.c',
  'polkitsystembusname.c',
  'polkittemporaryauthorization.c',
  'polkitunixgroup.c',
  'polkitunixnetgroup.c',
  'polkitunixprocess.c',
  'polkitunixuser.c',
)

incs = [
  top_inc,
  src_inc,
]

deps = common_deps

c_flags = '-D_POLKIT_COMPILATION'

if enable_logind
  sources += 'polkitunixsession-systemd.c'

  deps += logind_dep
else
  sources += 'polkitunixsession.c'
endif

libpolkit_gobject = shared_library(
  name,
  sources: sources,
  version: libversion,
  include_directories: incs,
  dependencies: deps,
  c_args: c_flags,
  link_args: ldflags,
  link_depends: symbol_map,
  install: true,
)

libpolkit_gobject_dep = declare_dependency(
  sources: enum_sources[1],
  include_directories: src_inc,
  dependencies: common_deps,
  link_with: libpolkit_gobject,
)

pkg.generate(
  libraries: libpolkit_gobject,
  version: pk_version,
  name: name,
  description: 'PolicyKit Authorization API',
  filebase: name,
  subdirs: pk_api_name,
  requires: common_deps,
  variables: [
    'exec_prefix=${prefix}',
    'datadir=' + ('${prefix}' / pk_datadir),
    'policydir=' + ('${datadir}' / pk_actiondir),
    'actiondir=' + ('${datadir}' / pk_actiondir),
    'pkcheck_supports_uid=true',
  ],
)

if enable_introspection
  libpolkit_gobject_gir = gnome.generate_gir(
    libpolkit_gobject,
    sources: sources + headers,
    extra_args: c_flags,
    nsversion: pk_gir_version,
    namespace: pk_gir_ns,
    export_packages: name,
    includes: 'Gio-2.0',
    header: 'polkit/polkit.h',
    install: true,
  )
endif

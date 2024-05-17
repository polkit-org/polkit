project(
  'polkit', ['c'],
  version: '127',
  license: 'LGPL2+',
  default_options: [
    'buildtype=debugoptimized',
    'prefix=/usr',
    'c_std=c99',
    'cpp_std=c++17',
  ],
  meson_version: '>= 1.4.0',
)

pk_version = meson.project_version()

pk_api_version = '1'
pk_api_name = '@0@-@1@'.format(meson.project_name(), pk_api_version)

pk_gir_ns = 'Polkit'
pk_gir_version = '1.0'

pk_prefix = get_option('prefix')
pk_datadir = get_option('datadir')
pk_includedir = get_option('includedir')
pk_libdir = get_option('libdir')
pk_mandir = get_option('mandir')
pk_sysconfdir = get_option('sysconfdir')

pk_pkgdatadir = pk_datadir / pk_api_name
pk_pkgincludedir = pk_includedir / pk_api_name
# note that this is always 'lib', not lib64 or lib/x86_64-linux-gnu
pk_libprivdir = 'lib' / pk_api_name
pk_pkgsysconfdir = pk_sysconfdir / pk_api_name

pk_actiondir = pk_api_name / 'actions'
pk_pkgactiondir = pk_datadir / pk_actiondir

soversion = 0
current = 0
revision = 0
libversion = '@0@.@1@.@2@'.format(soversion, current, revision)

gnome = import('gnome')
i18n = import('i18n')
pkg = import('pkgconfig')

source_root = meson.current_source_dir()
build_root = meson.current_build_dir()

data_dir = source_root / 'data'
its_dir = source_root / 'gettext'
po_dir = source_root / 'po'

its_data = files(
  'gettext/its/polkit.its',
  'gettext/its/polkit.loc',
)

install_data(
  its_data,
  install_dir: pk_datadir / 'gettext/its',
)

top_inc = include_directories('.')

cc = meson.get_compiler('c')

config_data = configuration_data()

# defines
set_defines = [
  # package
  ['PACKAGE_BUGREPORT', 'https://gitlab.freedesktop.org/polkit/polkit/-/issues/'],
  ['PACKAGE_NAME', meson.project_name()],
  ['PACKAGE_URL', 'http://www.freedesktop.org/wiki/Software/polkit'],
  ['PACKAGE_VERSION', pk_version],
  ['VERSION', pk_version],
  # i18n
  ['GETTEXT_PACKAGE', pk_api_name],
]

foreach define: set_defines
  config_data.set_quoted(define[0], define[1])
endforeach

# functions
check_functions = [
  'clearenv',
  'fdatasync',
  'setnetgrent',
]

foreach func: check_functions
  config_data.set('HAVE_' + func.to_upper(), cc.has_function(func))
endforeach

compiler_common_flags = [
  '-D_GNU_SOURCE',
]
compiler_c_flags = []
compiler_cpp_flags = []

if get_option('buildtype').contains('debug')
  compiler_c_flags += cc.get_supported_arguments([
    '-Waggregate-return',
    '-Wdeclaration-after-statement',
    '-Wformat=2',
    '-Wimplicit-function-declaration',
    '-Winit-self',
    '-Wmissing-declarations',
    '-Wmissing-include-dirs',
    '-Wmissing-prototypes',
    '-Wstrict-prototypes',
  ])
endif

compiler_c_flags += cc.get_supported_arguments([
  '-Wno-format-y2k',
  '-Wno-declaration-after-statement',
])

if cc.get_id() == 'gcc'
  compiler_c_flags += cc.get_supported_arguments([
    # -Wunused-result can't be suppressed by using (void) in gcc, so let's disable it for now
    # See: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425
    '-Wno-unused-result',
  ])
endif

glib_req_version = '>= 2.30.0'

gio_dep = dependency('gio-2.0', version: glib_req_version)
gio_unix_dep = dependency('gio-unix-2.0', version: glib_req_version)
glib_dep = dependency('glib-2.0', version: glib_req_version)
gobject_dep = dependency('gobject-2.0', version: glib_req_version)

duktape_req_version = '>= 2.2.0'

libs_only = get_option('libs-only')
if not libs_only
  expat_dep = dependency('expat')
  assert(cc.has_header('expat.h', dependencies: expat_dep), 'Can\'t find expat.h. Please install expat.')
  assert(cc.has_function('XML_ParserCreate', dependencies: expat_dep), 'Can\'t find expat library. Please install expat.')

  js_dep = dependency('duktape', version: duktape_req_version, required: false)
  if not js_dep.found()
    message('Falling back to looking for library and header...')
    js_dep = cc.find_library('duktape', has_headers: ['duktape.h'], required: true)
  endif
  libm_dep = cc.find_library('m')
  thread_dep = dependency('threads')
  func = 'pthread_condattr_setclock'
  config_data.set('HAVE_' + func.to_upper(), cc.has_function(func, prefix : '#include <pthread.h>'))
endif

dbus_dep = dependency('dbus-1', required: false)
dbus_policydir = pk_prefix / pk_datadir / 'dbus-1/system.d'
if dbus_dep.found()
  dbus_system_bus_services_dir = dbus_dep.get_variable(pkgconfig: 'system_bus_services_dir', pkgconfig_define: ['datadir', pk_prefix / pk_datadir])
else
  # libdbus development files not installed, assume a standard layout
  dbus_system_bus_services_dir = pk_prefix / pk_datadir / 'dbus-1' / 'system-services'
endif

# check OS
host_system = host_machine.system()
config_data.set('HAVE_' + host_system.to_upper(), true)

# Check whether setnetgrent has a return value
have_netgroup_h = cc.has_header('netgroup.h')
config_data.set('HAVE_NETGROUP_H', have_netgroup_h)

if config_data.get('HAVE_SETNETGRENT', false)
  setnetgrent_return_src = '''
    #include <stddef.h>
    #ifdef HAVE_NETGROUP_H
    #include <netgroup.h>
    #else
    #include <netdb.h>
    #endif
    int main() {
        int r = setnetgrent (NULL);
    };
  '''

  args = ['-D_GNU_SOURCE']
  if have_netgroup_h
    args += '-DHAVE_NETGROUP_H'
  endif
  config_data.set('HAVE_SETNETGRENT_RETURN', cc.compiles(setnetgrent_return_src, args: args, name: 'setnetgrent return support'))
endif

# Select wether to use logind, elogind or ConsoleKit for session tracking
session_tracking = get_option('session_tracking')
enable_logind = (session_tracking != 'ConsoleKit')
if enable_logind
  if session_tracking == 'logind'
    logind_dep = dependency('libsystemd', not_found_message: 'logind support requested but libsystemd library not found')
  else
    logind_dep = dependency('libelogind', not_found_message: 'elogind support requested but libelogind library not found')
  endif

  func = 'sd_uid_get_display'
  config_data.set10('HAVE_' + func.to_upper(), cc.has_function(func, dependencies: logind_dep))
  func = 'sd_pidfd_get_session'
  config_data.set10('HAVE_' + func.to_upper(), cc.has_function(func, dependencies: logind_dep))
endif
config_data.set('HAVE_LIBSYSTEMD', enable_logind)

config_data.set('HAVE_PIDFD_OPEN', cc.get_define('SYS_pidfd_open', prefix: '#include <sys/syscall.h>') != '')

# systemd unit / sysuser / tmpfiles.d file installation directories
systemdsystemunitdir = get_option('systemdsystemunitdir')
systemd_dep = dependency('systemd', required : false)
if systemd_dep.found()
  if systemdsystemunitdir == ''
    # FIXME: systemd.pc file does not use variables with relative paths, so `define_variable` cannot be used
    systemdsystemunitdir = systemd_dep.get_variable(pkgconfig : 'systemdsystemunitdir')
  endif
  sysusers_dir = systemd_dep.get_variable(pkgconfig : 'sysusers_dir')
  tmpfiles_dir = systemd_dep.get_variable(pkgconfig : 'tmpfiles_dir')
else
  if systemdsystemunitdir == ''
    systemdsystemunitdir = '/usr/lib/systemd/system'
  endif
  sysusers_dir = '/usr/lib/sysusers.d'
  tmpfiles_dir = '/usr/lib/tmpfiles.d'
endif

# User for running polkitd
polkitd_user = get_option('polkitd_user')
config_data.set_quoted('POLKITD_USER', polkitd_user)

polkitd_uid = get_option('polkitd_uid')
config_data.set('POLKITD_UID', polkitd_uid)

# Select which authentication framework to use
auth_deps = []

auth_fw = get_option('authfw')
enable_pam = (auth_fw == 'pam')
if enable_pam
  # Check for PAM
  pam_dep = cc.find_library('pam')
  assert(pam_dep.found() and cc.has_function('pam_start', dependencies: pam_dep), 'Could not find pam/pam-devel, please install the needed packages.')

  # how to call pam_strerror
  pam_strerror_src = '''
    #include <stdio.h>
    #include <stdlib.h>
    #include <security/pam_appl.h>
    #endif
    int main() {
      @0@
    };
  '''

  # FIXME: Not necessary anymore?
  if cc.compiles(pam_strerror_src.format('pam_handle_t *pamh = 0; char *s = pam_strerror(pamh, PAM_SUCCESS);'))
    # FIXME: unused?
    config_data.set('PAM_STRERROR_TWO_ARGS', true)
  else
    message('how to call pam_strerror: ' + cc.compiles(pam_strerror_src.format('char *s = pam_strerror(PAM_SUCCESS);')).to_string('1', 'unknown'))
  endif

  pam_prefix = get_option('pam_prefix')
  if pam_prefix == ''
    pam_prefix = pk_prefix / 'lib/pam.d'
  else
    message('PAM files will be installed in prefix ' + pam_prefix)
  endif

  pam_module_dir = get_option('pam_module_dir')
  if pam_module_dir == ''
    pam_module_dir = pk_libdir / 'security'
  endif

  auth_deps += pam_dep
elif auth_fw == 'shadow'
  auth_deps += cc.find_library('crypt')
endif
config_data.set('POLKIT_AUTHFW_' + auth_fw.to_upper(), true)

# FIXME: sigtimedwait is not used anywhere?
'''
if host_system == 'solaris'
  rt_dep = cc.find_library('rt')
  cc.has_function('sigtimedwait', dependencies: rt_dep)
else
  cc.has_function('sigtimedwait')
endif
'''

os_type = get_option('os_type')
if os_type == ''
  os_paths = [
    ['redhat', '/etc/sysconfig/network-scripts'],
    ['suse', '/etc/SuSE-release'],
    ['debian', '/etc/debian_version'],
    ['gentoo', '/etc/gentoo-release'],
    ['pardus', '/etc/pardus-release'],
    ['lfs', '/etc/lfs-release'],
  ]

  foreach os_path: os_paths
    if run_command('test', '-e', os_path[1], check: false).returncode() == 0
      os_type = os_path[0]
      break
    endif
  endforeach

  if os_type == ''
    message('Linux distribution autodetection failed, specify the distribution to target using -Dos_type=')
  endif
endif

# The default privileged group differs between distributions, set it accordingly if not specified
privileged_group = get_option('privileged_group')
if privileged_group == ''
  if os_type == 'debian'
    privileged_group = 'sudo'
  else
    privileged_group = 'wheel'
  endif
endif

pam_include = get_option('pam_include')
if pam_include == ''
  if ['suse', 'solaris', 'openembedded'].contains(os_type)
    pam_conf = {
      'PAM_FILE_INCLUDE_AUTH': 'common-auth',
      'PAM_FILE_INCLUDE_ACCOUNT': 'common-account',
      'PAM_FILE_INCLUDE_PASSWORD': 'common-password',
      'PAM_FILE_INCLUDE_SESSION': 'common-session',
    }
  elif os_type.contains('bsd')
    pam_conf = {
      'PAM_FILE_INCLUDE_AUTH': 'system',
      'PAM_FILE_INCLUDE_ACCOUNT': 'system',
      'PAM_FILE_INCLUDE_PASSWORD': 'system',
      'PAM_FILE_INCLUDE_SESSION': 'system',
    }
  elif os_type == 'lfs'
    pam_conf = {
      'PAM_FILE_INCLUDE_AUTH': 'system-auth',
      'PAM_FILE_INCLUDE_ACCOUNT': 'system-account',
      'PAM_FILE_INCLUDE_PASSWORD': 'system-password',
      'PAM_FILE_INCLUDE_SESSION': 'system-session',
    }
  #if ['redhat', 'gentoo', 'pardus'].contains(os_type)
  else
    pam_conf = {
      'PAM_FILE_INCLUDE_AUTH': 'system-auth',
      'PAM_FILE_INCLUDE_ACCOUNT': 'system-auth',
      'PAM_FILE_INCLUDE_PASSWORD': 'system-auth',
      'PAM_FILE_INCLUDE_SESSION': 'system-auth',
    }
  endif
else
  pam_conf = {
    'PAM_FILE_INCLUDE_AUTH': pam_include,
    'PAM_FILE_INCLUDE_ACCOUNT': pam_include,
    'PAM_FILE_INCLUDE_PASSWORD': pam_include,
    'PAM_FILE_INCLUDE_SESSION': pam_include,
  }
endif

enable_introspection = get_option('introspection')
if enable_introspection
  dependency('gobject-introspection-1.0', version: '>= 0.6.2')
endif

gettext = get_option('gettext')
if gettext
  config_data.set('ENABLE_GETTEXT', 1)
endif

configure_file(
  output: 'config.h',
  configuration: config_data,
)

compiler_common_flags += ['-include', 'config.h']

add_project_arguments(compiler_common_flags + compiler_c_flags, language: 'c')
add_project_arguments(compiler_common_flags + compiler_cpp_flags, language: 'cpp')

content_files = files('COPYING')

subdir('actions')
subdir('data')
subdir('src')
subdir('docs')
subdir('po')

enable_tests = get_option('tests')
if enable_tests
  subdir('test')
endif

if not libs_only
  meson.add_install_script(
    'meson_post_install.py',
    get_option('bindir'),
    pk_libprivdir,
    pk_pkgsysconfdir,
    polkitd_user,
  )
endif

output = '\n        ' + meson.project_name() + ' ' + meson.project_version() + '\n'
output += '        ============\n\n'
output += '        prefix:                   ' + pk_prefix + '\n'
output += '        datadir:                  ' + pk_datadir + '\n\n'
output += '        includedir:               ' + pk_includedir + '\n'
output += '        libdir:                   ' + pk_libdir + '\n'
output += '        sysconfdir:               ' + pk_sysconfdir + '\n'
output += '        source code location:     ' + source_root + '\n'
output += '        compiler:                 ' + cc.get_id() + '\n'
output += '        c_flags:                  ' + ' '.join(compiler_c_flags) + '\n\n'
if enable_man
  output += '        xsltproc:                 ' + xsltproc.full_path() + '\n'
endif
output += '        introspection:            ' + enable_introspection.to_string() + '\n'
output += '        Distribution/OS:          ' + os_type + '\n'
output += '        Authentication framework: ' + auth_fw + '\n'
output += '        Session tracking:         ' + session_tracking + '\n'
output += '        system unit directory:    ' + systemdsystemunitdir + '\n'
output += '        sysusers.d directory:     ' + sysusers_dir + '\n'
output += '        tmpfiles.d directory:     ' + tmpfiles_dir + '\n'

output += '        polkitd user:             ' + polkitd_user + ' \n'
if polkitd_uid != '-'
  output += '        polkitd UID:              ' + polkitd_uid + ' \n'
endif
output += '        PAM support:              ' + enable_pam.to_string() + '\n\n'
if libs_only
  output += '    !!! Only building polkit libraries, not polkitd !!!\n\n'
endif
if enable_pam
  output += '        PAM file auth:            ' + pam_conf['PAM_FILE_INCLUDE_AUTH'] + '\n'
  output += '        PAM file acount:          ' + pam_conf['PAM_FILE_INCLUDE_ACCOUNT'] + '\n'
  output += '        PAM file password:        ' + pam_conf['PAM_FILE_INCLUDE_PASSWORD'] + '\n'
  output += '        PAM file session:         ' + pam_conf['PAM_FILE_INCLUDE_SESSION'] + '\n'
  output += '        PAM config location:      ' + pam_prefix + '\n\n'
endif
output += '        Building api docs:        ' + enable_gtk_doc.to_string() + '\n'
output += '        Building man pages:       ' + enable_man.to_string() + '\n'
output += '        Building examples:        ' + enable_examples.to_string() + '\n'
output += '        Building tests:           ' + enable_tests.to_string()
message(output)

libpolkit_test_helper = static_library(
  'polkit-test-helper',
  sources: 'polkittesthelper.c',
  dependencies: glib_dep,
)

libpolkit_test_helper_dep = declare_dependency(
  include_directories: '.',
  dependencies: glib_dep,
  link_with: libpolkit_test_helper,
)

libmocklibc = subproject('mocklibc').get_variable('libmocklibc')

test_data_dir = meson.current_source_dir() / 'data'
test_etc_dir = test_data_dir / 'etc'

test_env = environment()
test_env.set('LD_PRELOAD', libmocklibc.full_path())
test_env.set('MOCK_PASSWD', test_etc_dir / 'passwd')
test_env.set('MOCK_GROUP', test_etc_dir / 'group')
test_env.set('MOCK_NETGROUP', test_etc_dir / 'netgroup')
test_env.set('POLKIT_TEST_DATA', test_data_dir)

subdir('polkit')
if not get_option('libs-only')
  subdir('polkitbackend')
endif

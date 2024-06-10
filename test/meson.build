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

test_wrapper = find_program('wrapper.py')
test_data_dir = meson.current_source_dir() / 'data'

subdir('polkit')
if not get_option('libs-only')
  subdir('polkitbackend')
endif

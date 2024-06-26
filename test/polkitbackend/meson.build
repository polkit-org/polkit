test_unit = 'test-polkitbackendjsauthority'

deps = [
  libpolkit_gobject_dep,
  libpolkit_test_helper_dep,
]

c_flags = [
  '-D_POLKIT_COMPILATION',
  '-D_POLKIT_BACKEND_COMPILATION',
]

exe = executable(
  test_unit,
  test_unit + '.c',
  include_directories: top_inc,
  dependencies: deps,
  c_args: c_flags,
  link_with: libpolkit_backend,
)

test(
  test_unit,
  test_wrapper,
  args: ['--data-dir', test_data_dir, '--mock-dbus', exe.full_path()],
  timeout: 90,
)

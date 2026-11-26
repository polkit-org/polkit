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

if enable_caller_tag
  test_unit = 'test-polkitbackendcallertag'

  exe = executable(
    test_unit,
    test_unit + '.c',
    include_directories: top_inc,
    dependencies: libpolkit_gobject_dep,
    c_args: c_flags,
    link_with: libpolkit_backend,
  )

  test(test_unit, exe, timeout: 30)

  test(
    'test-caller-tag',
    test_wrapper,
    args: ['--data-dir', test_data_dir, '--mock-dbus',
           'python3 @0@ @1@'.format(meson.current_source_dir() / 'test-caller-tag.py', polkitd_exe.full_path())],
    depends: polkitd_exe,
    timeout: 60,
  )
endif

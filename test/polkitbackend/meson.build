test_unit = 'test-polkitbackendjsauthority'

deps = [
  libpolkit_gobject_dep,
  libpolkit_test_helper_dep,
]

c_flags = [
  '-D_POLKIT_COMPILATION',
  '-D_POLKIT_BACKEND_COMPILATION',
]

test_env.set('TOP_BUILD_DIR', build_root)
test_env.set('TOP_SRC_DIR', source_root)

exe = executable(
  test_unit,
  test_unit + '.c',
  include_directories: top_inc,
  dependencies: deps,
  c_args: c_flags,
  link_with: libpolkit_backend,
)

prog = find_program('polkitbackendjsauthoritytest-wrapper.py')

test(
  test_unit,
  prog,
  env: test_env,
  is_parallel: false,
  timeout: 90,
)

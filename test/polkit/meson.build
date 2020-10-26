test_units = [
  'polkitunixusertest',
  'polkitunixgrouptest',
  'polkitunixnetgrouptest',
  'polkitidentitytest',
]

c_flags = [
  '-D_POLKIT_COMPILATION',
  '-D_POLKIT_BACKEND_COMPILATION',
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: libpolkit_gobject_dep,
    c_args: c_flags,
  )

  test(
    test_unit,
    exe,
    env: test_env,
    is_parallel: false,
  )
endforeach

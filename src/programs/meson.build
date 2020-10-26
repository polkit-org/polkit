programs = [
  ['pkexec', auth_deps + [libpolkit_agent_dep]],
  ['pkcheck', [libpolkit_agent_dep]],
  ['pkaction', [libpolkit_gobject_dep]],
  ['pkttyagent', [libpolkit_agent_dep]],
]

foreach program: programs
  executable(
    program[0],
    program[0] + '.c',
    include_directories: top_inc,
    dependencies: program[1],
    install: true,
  )
endforeach

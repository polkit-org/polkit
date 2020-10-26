src_inc = include_directories('.')

symbol_map = meson.current_source_dir() / 'symbol.map'
ldflags = cc.get_supported_link_arguments('-Wl,--version-script,@0@'.format(symbol_map))

subdir('polkit')
subdir('polkitbackend')
subdir('polkitagent')
subdir('programs')

enable_examples = get_option('examples')
if enable_examples
  subdir('examples')
endif

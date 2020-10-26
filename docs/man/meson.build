xsltproc = find_program('xsltproc', required: false)
assert(xsltproc.found(), 'xsltproc is required for man pages generation')

xsltproc_cmd = [
  xsltproc,
  '--output', '@OUTPUT@',
  '--nonet',
  '--stringparam', 'man.base.url.for.relative.links', pk_api_docpath + '/',
  'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
  '@INPUT@',
]

mans = [
  ['polkit', '8'],
  ['polkitd', '8'],
  ['pkexec', '1'],
  ['pkcheck', '1'],
  ['pkaction', '1'],
  ['pkttyagent', '1'],
]

foreach man: mans
  xml = files(man[0] + '.xml')
  content_files += xml

  output = '@0@.@1@'.format(man[0], man[1])

  custom_target(
    output,
    input: xml,
    output: output,
    command: xsltproc_cmd,
    install: true,
    install_dir: pk_mandir / ('man' + man[1]),
  )
endforeach

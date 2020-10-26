#!/usr/bin/env python3

import getpass
import os
import subprocess
import sys

prefix = os.environ['MESON_INSTALL_DESTDIR_PREFIX']

bindir = os.path.join(prefix, sys.argv[1])
pkgdatadir = os.path.join(prefix, sys.argv[2])
pkglibdir = os.path.join(prefix, sys.argv[3])
pkgsysconfdir = os.path.join(prefix, sys.argv[4])

polkitd_user = sys.argv[5]

subprocess.check_call(['chmod', '4755', os.path.join(bindir, 'pkexec')])

dst_dirs = [
    os.path.join(pkgsysconfdir, 'rules.d'),
    os.path.join(pkgdatadir, 'rules.d')
]

for dst in dst_dirs:
    if not os.path.exists(dst):
        os.makedirs(dst)
        subprocess.check_call(['chmod', '700', dst])
        if getpass.getuser() == "root":
            subprocess.check_call(['chown', polkitd_user, dst])

# polkit-agent-helper-1 need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users.
dst = os.path.join(pkglibdir, 'polkit-agent-helper-1')
subprocess.check_call(['chmod', '4755', dst])
if getpass.getuser() == "root":
    subprocess.check_call(['chown', 'root', dst])

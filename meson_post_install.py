#!/usr/bin/env python3

import getpass
import os
import pwd
import sys

prefix = os.environ['MESON_INSTALL_DESTDIR_PREFIX']

bindir = os.path.join(prefix, sys.argv[1])
pkgdatadir = os.path.join(prefix, sys.argv[2])
pkglibdir = os.path.join(prefix, sys.argv[3])
pkgsysconfdir = os.path.join(prefix, sys.argv[4])

polkitd_uid = pwd.getpwnam(sys.argv[5]).pw_uid

os.chmod(os.path.join(bindir, 'pkexec'), 0o4775)

dst_dirs = [
    os.path.join(pkgsysconfdir, 'rules.d'),
    os.path.join(pkgdatadir, 'rules.d')
]

for dst in dst_dirs:
    if not os.path.exists(dst):
        os.makedirs(dst, mode=0o700)
        if getpass.getuser() == "root":
            os.chown(dst, polkitd_uid, -1)

# polkit-agent-helper-1 need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users.
dst = os.path.join(pkglibdir, 'polkit-agent-helper-1')
os.chmod(dst, 0o4755)
if getpass.getuser() == "root":
    os.chown(dst, 0, -1)

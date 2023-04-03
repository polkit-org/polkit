#!/usr/bin/env python3

import os
import pwd
import sys

destdir = os.environ.get('DESTDIR')
prefix = os.environ['MESON_INSTALL_DESTDIR_PREFIX']

def destdir_path(p):
    if os.path.isabs(p):
        if destdir is None:
            return p
        else:
            return os.path.join(destdir, os.path.relpath(p, '/'))
    else:
        return os.path.join(prefix, p)

bindir = destdir_path(sys.argv[1])
pkglibdir = destdir_path(sys.argv[2])
pkgsysconfdir = destdir_path(sys.argv[3])
polkitd_user = sys.argv[4]

try:
    polkitd_gid = pwd.getpwnam(polkitd_user).pw_gid
except KeyError:
    polkitd_gid = None

dst = os.path.join(bindir, 'pkexec')

if os.geteuid() == 0:
    os.chown(dst, 0, -1)
    os.chmod(dst, 0o4755)
else:
    print(
        'Owner and mode of {} need to be setuid root (04755) after '
        'installation'.format(
            dst,
        )
    )

dst = os.path.join(pkgsysconfdir, 'rules.d')

if not os.path.exists(dst):
    os.makedirs(dst, mode=0o750)
    if os.geteuid() == 0 and polkitd_gid is not None:
        os.chown(dst, 0, polkitd_gid)
    else:
        print(
            'Owner of {} needs to be set to root and group to {} after installation'.format(
                dst, polkitd_user,
            )
        )

# polkit-agent-helper-1 need to be setuid root because it's used to
# authenticate not only the invoking user, but possibly also root
# and/or other users.
dst = os.path.join(pkglibdir, 'polkit-agent-helper-1')

if os.geteuid() == 0:
    os.chown(dst, 0, -1)
    os.chmod(dst, 0o4755)
else:
    print(
        'Owner and mode of {} need to be setuid root (04755) after '
        'installation'.format(
            dst,
        )
    )

#!/usr/bin/python3

# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your option) any
# later version.  See http://www.gnu.org/copyleft/lgpl.html for the full text
# of the license.

__author__ = 'Bastien Nocera'
__email__ = 'hadess@hadess.net'
__copyright__ = '(c) 2020 Red Hat Inc.'
__license__ = 'LGPL 3+'

import unittest
import sys
import subprocess
import dbus
import dbus.mainloop.glib
import dbusmock
import os
import time

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

class TestPolkitBackendJsAuthority(dbusmock.DBusTestCase):
    '''Test polkitbackendjsauthoritytest'''

    @classmethod
    def setUpClass(klass):
        klass.start_system_bus()
        klass.mocklibc_path = None

        if 'TOP_BUILD_DIR' in os.environ:
            klass.top_build_dir = os.environ['TOP_BUILD_DIR']
            klass.mocklibc_path = klass.top_build_dir  + '/subprojects/mocklibc-1.0/bin/mocklibc'

        # suppose autotools over meson
        if not os.path.exists(klass.mocklibc_path):
            klass.top_build_dir = '../../'
            klass.mocklibc_path = klass.top_build_dir + '/test/mocklibc/bin/mocklibc'
        print ('Top build dir: %s' % klass.top_build_dir)
        print ('mocklibc path: %s' % klass.mocklibc_path)
        assert(os.path.exists(klass.mocklibc_path))

        # WORKAROUND - unzipped mocklibc does not preserve file permissions
        os.chmod(klass.mocklibc_path, 0o755)

        klass.top_src_dir = os.path.dirname(os.path.realpath(__file__)) + '/../../'
        if 'TOP_SRC_DIR' in os.environ:
            klass.top_src_dir = os.environ['TOP_SRC_DIR']
        print ('Top source dir: %s' % klass.top_src_dir)

        os.environ['POLKIT_TEST_DATA'] = klass.top_src_dir + '/test/data'
        print ('Polkit test data dir: %s' % os.environ['POLKIT_TEST_DATA'])

        os.environ['MOCK_PASSWD'] = klass.top_src_dir + '/test/data/etc/passwd'
        print ('Mock password file: %s' % os.environ['MOCK_PASSWD'])
        os.environ['MOCK_GROUP'] = klass.top_src_dir + '/test/data/etc/group'
        print ('Mock group file: %s' % os.environ['MOCK_GROUP'])
        os.environ['MOCK_NETGROUP'] = klass.top_src_dir + '/test/data/etc/netgroup'
        print ('Mock netgroup file: %s' % os.environ['MOCK_NETGROUP'])

    def test_polkitbackendjsauthoritytest(self):
        # Add '; exit 0' at the end of the cmd line if launching fails and you
        # want to capture the error output
        test_path = self.top_build_dir + '/test/polkitbackend/test-polkitbackendjsauthority'

        if not os.path.exists(test_path):
            print('\n %s... not found' % test_path)
            test_path = self.top_build_dir + '/test/polkitbackend/polkitbackendjsauthoritytest'

        out = subprocess.check_output(self.mocklibc_path + ' ' + test_path,
                                      stderr=subprocess.STDOUT,
                                      shell=True,
                                      universal_newlines=True)
        print(out)

if __name__ == '__main__':
    # avoid writing to stderr
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))

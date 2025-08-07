#!/usr/bin/env python3

import argparse
import atexit
import os
import subprocess
import sys

import dbus
import dbus.mainloop.glib
import dbusmock


def setup_test_namespace(data_dir):
    print(f"Test data dir: {data_dir}")

    # Setup a new mount & user namespace, so we can use mount() unprivileged (see user_namespaces(7))
    euid = os.geteuid()
    egid = os.getegid()
    try:
        os.unshare(os.CLONE_NEWNS|os.CLONE_NEWUSER)
        # Map root to the original EUID and EGID, so we can actually call mount() inside our namespace
        with open("/proc/self/uid_map", "w") as f:
            f.write(f"0 {euid} 1")
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/gid_map", "w") as f:
            f.write(f"0 {egid} 1")

        # Overmount /etc with our own version
        subprocess.check_call(["mount", "--bind", os.path.join(data_dir, "etc"), "/etc"])
    except PermissionError:
        print("Lacking permissions to set up test harness, skipping")
        sys.exit(77)
    except AttributeError:
        print("Python 3.12 is required for os.unshare(), skipping")
        sys.exit(77)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("test_executable",
                        help="test executable to run in our own test namespace")
    parser.add_argument("--data-dir", type=str, required=True,
                        help="path to test data directory (with our own /etc/{passwd,group,...} files)")
    parser.add_argument("--mock-dbus", action="store_true",
                        help="set up a mock system D-Bus using dbusmock")
    args = parser.parse_args()

    setup_test_namespace(args.data_dir)

    if args.mock_dbus:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        dbusmock.DBusTestCase.start_system_bus()
        atexit.register(dbusmock.DBusTestCase.stop_dbus, dbusmock.DBusTestCase.system_bus_pid)

    print(f"Executing '{args.test_executable}'")
    sys.stdout.flush()
    os.environ["POLKIT_TEST_DATA"] = args.data_dir
    subprocess.check_call(args.test_executable, shell=True)

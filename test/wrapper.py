#!/usr/bin/env python3

import argparse
import atexit
import os
import platform
import subprocess
import shutil
import sys
import signal
import time
import errno

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
        return False
    except AttributeError:
        print("Python 3.12 is required for os.unshare(), skipping")
        return False
    except OSError as e:
        if e.errno == errno.EINVAL:
            print("os.unshare(os.CLONE_NEWNS|os.CLONE_NEWUSER) not supported, skipping")
            return False
        raise
    return True


def stop_dbus(pid: int) -> None:
    """Stop a D-Bus daemon

    If DBus daemon is not explicitly killed in the testing environment
    the test times out and reports as failed.
    This is a backport of a function dropped from DBusMock source (99c4800e9eed).
    """
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    for _ in range(50):
        try:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        except OSError as e:
            if e.errno == errno.ESRCH:
                break
            raise
        time.sleep(0.1)
    else:
        sys.stderr.write("ERROR: timed out waiting for bus process to terminate\n")
        os.kill(pid, signal.SIGKILL)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def setup_test_unconstrained_linux(data_dir):
    shutil.copytree(os.path.join(data_dir, "etc"), "/etc", dirs_exist_ok=True)

def setup_test_unconstrained_freebsd(data_dir):
    shutil.copytree(os.path.join(data_dir, "etc"), "/etc", dirs_exist_ok=True)
    with open("/etc/master.passwd.freebsd", "r") as passwd:
        for entry in passwd:
            # Retry if the passwd DB is locked by something else
            while subprocess.call(["chpass", "-a", entry]) != 0:
                pass
    shutil.copy2("/etc/group.freebsd", "/etc/group")
    # Ping ConsoleKit to get it autostarted, because some tests end up
    # trying to access /var/lib/ConsoleKit/database
    bus = dbus.SystemBus()
    consolekit = bus.get_object("org.freedesktop.ConsoleKit", "/org/freedesktop/ConsoleKit/Manager")
    consolekit.GetSeats(dbus_interface="org.freedesktop.ConsoleKit.Manager")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("test_executable",
                        help="test executable to run in our own test namespace")
    parser.add_argument("--data-dir", type=str, required=True,
                        help="path to test data directory (with our own /etc/{passwd,group,...} files)")
    parser.add_argument("--mock-dbus", action="store_true",
                        help="set up a mock system D-Bus using dbusmock")
    args = parser.parse_args()

    if not setup_test_namespace(args.data_dir):
        # We might fail to setup an isolated environment for running tests
        # This might happen on Linux without unshare support or
        # on non-Linux OSes, like FreeBSD.
        # In this case, skip running tests by default, but allow them to be
        # executed if the user asks for it via special env var
        if os.getenv("ALLOW_SYSTEM_DESTRUCTIVE_TESTS") == "1":
            if platform.system() == 'FreeBSD':
                setup_test_unconstrained_freebsd(args.data_dir)
            else:
                setup_test_unconstrained_linux(args.data_dir)
        else:
            # skip tests
            sys.exit(77)

    if args.mock_dbus:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        dbusmock.DBusTestCase.start_system_bus()
        atexit.register(stop_dbus, dbusmock.DBusTestCase.system_bus_pid)

    print(f"Executing '{args.test_executable}'")
    sys.stdout.flush()
    os.environ["POLKIT_TEST_DATA"] = args.data_dir
    subprocess.check_call(args.test_executable, shell=True)

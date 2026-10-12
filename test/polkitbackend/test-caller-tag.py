#!/usr/bin/env python3
"""The real polkitd, on dbusmock's bus, resolving a caller tag through a
provider this process serves. Under wrapper.py we are uid 0 in a user
namespace and /etc comes from test/data."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import dbus

POLKITD = sys.argv[1]
PROVIDER = "io.test.Provider"
ACTION = "org.freedesktop.systemd1.manage-units"
REFERENCE = "0123456789abcdef"
# polkit authorizes uid 0 before consulting any rule, and under wrapper.py we
# are uid 0; claiming the subject is john (test passwd) makes rules run.
SUBJECT_UID = 500


def tag(provider=PROVIDER, reference=REFERENCE):
    return f"{reference}/caller-tag/{provider}"


def serve(sock, handle):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        with conn:
            buf = b""
            while b"\0" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            if b"\0" not in buf:
                continue
            reply = handle(json.loads(buf.split(b"\0", 1)[0]))
            if reply is not None:
                conn.sendall(json.dumps(reply).encode() + b"\0")


resolve_calls = []


def provider(call):
    resolve_calls.append(call)
    params = call.get("parameters", {})
    if (call.get("method") == f"{PROVIDER}.Resolve"
            and params.get("reference") == REFERENCE):
        return {"parameters": {"identity": {"mechanism": "test", "caller": "test-caller"}}}
    return {"parameters": {}}


def hanging_provider(call):
    time.sleep(5)  # longer than polkitd's timeout
    return provider(call)


def listen(path, handle):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(8)
    threading.Thread(target=serve, args=(s, handle), daemon=True).start()
    return s


def check(auth, pid, on_behalf_of):
    details = {"pid": dbus.UInt32(pid), "start-time": dbus.UInt64(0), "uid": dbus.Int32(SUBJECT_UID)}
    if on_behalf_of is not None:
        details["on-behalf-of"] = dbus.String(on_behalf_of)
    subject = dbus.Struct((dbus.String("unix-process"),
                           dbus.Dictionary(details, signature="sv")), signature="sa{sv}")
    authorized, challenge, _ = auth.CheckAuthorization(
        subject, ACTION, dbus.Dictionary({}, signature="ss"), dbus.UInt32(0), "")
    return bool(authorized), bool(challenge)


def main():
    providers = tempfile.mkdtemp(prefix="caller-tag-providers-")
    listen(os.path.join(providers, PROVIDER), provider)
    listen(os.path.join(providers, "io.test.Hangs"), hanging_provider)

    env = dict(os.environ, POLKIT_CALLER_TAG_PROVIDERS_DIR=providers)
    polkitd = subprocess.Popen([POLKITD, "--log-level=debug"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    bus = dbus.SystemBus()
    for _ in range(100):
        if bus.name_has_owner("org.freedesktop.PolicyKit1"):
            break
        if polkitd.poll() is not None:
            print(polkitd.stdout.read())
            sys.exit("polkitd exited during startup")
        time.sleep(0.1)
    else:
        polkitd.kill()
        print(polkitd.stdout.read())
        sys.exit("polkitd never claimed its bus name")

    auth = dbus.Interface(
        bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority"),
        "org.freedesktop.PolicyKit1.Authority")
    me, parent = os.getpid(), os.getppid()
    failed = []

    def expect(name, got, want):
        status = "ok  " if got == want else "FAIL"
        print(f"{status} {name}: authorized={got[0]} challenge={got[1]}")
        if got != want:
            failed.append(name)

    try:
        expect("tag resolves for our own pid", check(auth, me, tag()), (True, False))
        # the parent (wrapper.py) shares our cgroup, so polkit lets us vouch for it
        expect("same tag, subject is another pid in our unit", check(auth, parent, tag()), (True, False))
        # a request without a tag falls through to the default auth_admin challenge
        expect("no tag at all", check(auth, me, None), (False, True))
        # every tag that does not resolve is null to the rules, which say NO to that,
        # so none of these may look like the untagged case above
        before = len(resolve_calls)
        expect("same tag, but the subject is in another unit", check(auth, 1, tag()), (False, False))
        if len(resolve_calls) != before:
            failed.append("provider was consulted for a subject outside its unit")
        expect("provider does not know the reference", check(auth, me, tag(reference="fedcba9876543210")), (False, False))
        expect("provider does not exist", check(auth, me, tag(provider="io.test.Missing")), (False, False))
        expect("malformed tag", check(auth, me, "not-a-tag"), (False, False))
        expect("provider name escapes the directory", check(auth, me, tag(provider="../../etc/passwd")), (False, False))
        t0 = time.monotonic()
        expect("provider hangs", check(auth, me, tag(provider="io.test.Hangs")), (False, False))
        elapsed = time.monotonic() - t0
        print(f"     (hang case took {elapsed:.1f}s; polkitd's timeout is 1s)")
        if elapsed > 4:
            failed.append("timeout did not fire")
    finally:
        polkitd.terminate()
        try:
            out = polkitd.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            polkitd.kill()
            out = polkitd.communicate()[0]
        if failed:
            print("\n--- polkitd output ---\n" + out)

    if failed:
        sys.exit("FAILED: " + ", ".join(failed))
    print("all caller-tag cases passed")


if __name__ == "__main__":
    main()

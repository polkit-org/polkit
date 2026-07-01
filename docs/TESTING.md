# Testing

## Unit Tests

### Overview

Unit tests are built with Meson (enabled via `-Dtests=true`) and use the **GLib testing framework** (`g_test_*`, `g_assert_*`).
Each test is a standalone C executable that exercises a specific module from `src/polkit/` or `src/polkitbackend/`.

Tests are **not** run directly — they are invoked through a Python **wrapper script** (`test/wrapper.py`) that sets up an isolated environment with user/mount namespaces and, when needed, a mock D-Bus system bus via **python-dbusmock**.

### Location

```
test/
├── meson.build                  # top-level test build: helper lib, wrapper discovery, subdirs
├── wrapper.py                   # test harness: namespaces + dbusmock
├── polkittesthelper.c/h         # shared C helper (log redirection, test data path lookup)
├── polkit/                      # unit tests for libpolkit-gobject-1
│   ├── meson.build
│   ├── polkitidentitytest.c
│   ├── polkitunixusertest.c
│   ├── polkitunixgrouptest.c
│   └── polkitunixnetgrouptest.c
├── polkitbackend/               # unit tests for the authority backend
│   ├── meson.build
│   └── test-polkitbackendjsauthority.c
└── data/                        # test fixtures (fake /etc, rules, actions)
    ├── etc/passwd
    ├── etc/group
    ├── etc/netgroup
    ├── etc/polkit-1/rules.d/    # test .rules files
    └── usr/share/polkit-1/rules.d/
```

### Pipeline

The execution flow for each unit test is:

```
meson test
  └── test/wrapper.py --data-dir test/data [--mock-dbus] <test_executable>
        ├── 1. Create user + mount namespace (os.unshare)
        ├── 2. Map current UID/GID to root inside the namespace
        ├── 3. Bind-mount test/data/etc over /etc
        ├── 4. [if --mock-dbus] Start mock system D-Bus via dbusmock
        ├── 5. Set POLKIT_TEST_DATA=<data-dir>
        └── 6. Execute the test binary
              └── GLib g_test_run() drives individual test cases
```

### The Wrapper (`test/wrapper.py`)

The wrapper isolates tests from the host system:

1. **Namespace setup** — Creates `CLONE_NEWNS | CLONE_NEWUSER` to get an unprivileged mount namespace, then bind-mounts `test/data/etc` over `/etc` so tests see controlled `passwd`, `group`, and `netgroup` files.

2. **Mock D-Bus** (optional, `--mock-dbus`) — Uses `python-dbusmock` to start a private system bus. Required by backend tests that interact with D-Bus (e.g., the JS authority test).

3. **Environment** — Sets `POLKIT_TEST_DATA` pointing to the test data directory. The C helper function `polkit_test_get_data_path()` uses this to locate fixture files at runtime.

4. **Exit codes** — Returns 77 (skip) if the kernel doesn't support user namespaces or Python < 3.12.

### Test Helper Library (`polkittesthelper`)

A small static library (`libpolkit-test-helper`) linked by backend tests, providing:

- `polkit_test_redirect_logs()` — Routes GLib log messages through `g_test_message()` so they only appear with `--verbose`.
- `polkit_test_get_data_path(relpath)` — Resolves a relative path against `POLKIT_TEST_DATA`.

### Library Tests (`test/polkit/`)

Test the client-side `libpolkit-gobject-1` types:

| Test | What it exercises |
|------|-------------------|
| `polkitidentitytest` | `PolkitIdentity` interface: string serialization, equality, hashing |
| `polkitunixusertest` | `PolkitUnixUser`: creation, UID lookup against fake `/etc/passwd` |
| `polkitunixgrouptest` | `PolkitUnixGroup`: creation, GID lookup against fake `/etc/group` |
| `polkitunixnetgrouptest` | `PolkitUnixNetgroup`: netgroup name handling |

These tests do **not** require D-Bus — they only need the namespace/mount isolation for `/etc` overrides.

### Backend Tests (`test/polkitbackend/`)

Test the `polkitd` authority backend:

| Test | What it exercises |
|------|-------------------|
| `test-polkitbackendjsauthority` | Duktape JS rules engine: admin identities, authorization decisions, variables, group/netgroup membership, `polkit.spawn()`, runaway script termination |

This test **requires `--mock-dbus`** and has a longer timeout (90s) due to runaway-script-killer tests.
It instantiates `PolkitBackendJsAuthority` directly, loads rules from the test fixture directories, and verifies authorization decisions against expected outcomes.

### Test Data Fixtures (`test/data/`)

The fixture directory mirrors a minimal system layout:

- `etc/passwd`, `etc/group`, `etc/netgroup` — Controlled user/group databases with test users (`john`, `highuid2`, etc.)
- `etc/polkit-1/rules.d/*.rules` — JavaScript rules exercising various decision paths (admin rules, group checks, netgroup checks, spawning, timeouts)
- `usr/share/polkit-1/rules.d/*.rules` — Additional rules testing priority ordering between system and vendor directories

### Dependencies

To run unit tests you need:

- Python >= 3.12 (for `os.unshare()`)
- `python3-dbus`
- `python3-dbusmock`
- Linux kernel with user namespace support (`CONFIG_USER_NS=y`)
- Meson configured with `-Dtests=true`

### Running

```bash
meson setup builddir -Dtests=true
meson test -C builddir
```

Individual tests can be run with:
```bash
meson test -C builddir polkitidentitytest
meson test -C builddir test-polkitbackendjsauthority
```

Use `--verbose` to see GLib test log output.

---

## Integration Tests

Located in `test/integration/`, using TMT (Test Management Tool) with FMF metadata:

| Suite | What it tests |
|-------|---------------|
| `pkexec/` | `pkexec` authorization flow including authentication caching (uses `expect` scripts) |
| `dfuzzer/` | D-Bus interface fuzz testing of the running polkitd |
| `systemd/` | polkit-governed systemd unit operations (start/stop/restart with custom rules) |

Integration tests require a running system with polkit installed and are typically executed in CI VMs via `tmt run`.

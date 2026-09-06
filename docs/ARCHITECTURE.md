# polkit Repository Architecture

## Overview

polkit (formerly PolicyKit) is an application-level toolkit for defining and handling the policy that allows unprivileged processes to speak to privileged processes.
It is used to grant fine-grained control over system-wide privileges, enabling non-privileged users to perform specific administrative tasks without requiring full root access.

The project is split into a system daemon (`polkitd`), a client library (`libpolkit-gobject-1`), an authentication agent library (`libpolkit-agent-1`), and a set of command-line tools.

```
 ┌──────────────────────────┐        ┌────────────────────────────┐
 │  Privileged Application  │        │  Authentication Agent (UI) │
 │  (e.g. systemd, udisks)  │        │  (e.g. GNOME, KDE, pktty) │
 └────────────┬─────────────┘        └──────────────┬─────────────┘
              │                                      │
              │ libpolkit-gobject-1                   │ libpolkit-agent-1
              │ (D-Bus client proxy)                  │ (D-Bus object export)
              │                                      │
              ▼                                      ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                    System Bus (D-Bus)                             │
 │              org.freedesktop.PolicyKit1                           │
 └────────────────────────────────┬─────────────────────────────────┘
                                  │
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │                      polkitd (Authority Daemon)                   │
 │  ┌───────────────────────────────────────────────────────────┐   │
 │  │ PolkitBackendInteractiveAuthority                         │   │
 │  │  ├── PolkitBackendJsAuthority (Duktape rules engine)      │   │
 │  │  ├── PolkitBackendActionPool (action XML parsing)         │   │
 │  │  ├── PolkitBackendSessionMonitor (systemd/logind)         │   │
 │  │  └── TemporaryAuthorizationStore                          │   │
 │  └───────────────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  polkit-agent-helper-1 (setuid / socket-activated helper)        │
 │  Performs PAM/shadow/bsdauth authentication conversation         │
 └──────────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

| Directory | Description |
|-----------|-------------|
| `src/polkit/` | Client-side shared library (`libpolkit-gobject-1.so`). GObject types for subjects, identities, authorization results, and the D-Bus proxy to the authority daemon. |
| `src/polkitagent/` | Authentication agent shared library (`libpolkit-agent-1.so`). GObject types for agent listeners, sessions, and the setuid authentication helper binary. |
| `src/polkitbackend/` | Authority daemon backend (static library linked into `polkitd`). GObject class hierarchy for the authority, JavaScript rules engine (Duktape), action pool, session monitor, and the `polkitd` main entry point. |
| `src/programs/` | Command-line tools: `pkaction`, `pkcheck`, `pkexec`, `pkttyagent`. |
| `src/examples/` | Example programs demonstrating API usage. |
| `data/` | D-Bus interface XML files, systemd unit files, sysusers/tmpfiles configs, PAM configuration templates, D-Bus bus policy config, and pkg-config `.pc` templates. |
| `actions/` | Shipped policy action definition files (`.policy.in` XML). |
| `docs/` | gtk-doc API reference sources, man page XML sources, architecture diagrams. |
| `docs/man/` | Man page XML source files for all command-line tools and daemon. |
| `test/` | Unit tests (`test/polkit/`, `test/polkitbackend/`) and integration tests (`test/integration/`) using TMT/FMF. |
| `po/` | Gettext translation catalogs. |
| `gettext/` | ITS (Internationalization Tag Set) rules for translating policy XML files. |
| `.github/` | GitHub CI workflow definitions. |
| `.packit/` | Packit/Copr downstream integration configuration. |

---

## Component Architecture

### The Authority Daemon (`polkitd`)

The daemon is the central decision-making component.
It runs as a D-Bus system service under the bus name `org.freedesktop.PolicyKit1`, registered at object path `/org/freedesktop/PolicyKit1/Authority`.

**Entry point:** `src/polkitbackend/polkitd.c`

The daemon's `main()` function:
1. Drops privileges to the `polkitd` system user via `become_user()`
2. Instantiates the authority backend via `polkit_backend_authority_get()`
3. Owns the well-known D-Bus name using `g_bus_own_name()`
4. Registers the authority object on the acquired bus connection
5. Enters a `GMainLoop` event loop
6. Handles `SIGHUP` for live configuration reload and `SIGINT`/`SIGTERM` for clean shutdown

**Class hierarchy:**
```
GObject
 └── PolkitBackendAuthority (abstract base)
      └── PolkitBackendInteractiveAuthority (agent interaction, temporary authorizations)
           └── PolkitBackendJsAuthority (Duktape JavaScript rules evaluation)
```

Key subcomponents:
- **`PolkitBackendActionPool`** — Parses `.policy` XML files from action directories and provides action metadata lookup.
- **`PolkitBackendSessionMonitor`** — Monitors login sessions via `sd_login_monitor` (systemd-logind), determining session locality and user-to-session mapping.
- **`TemporaryAuthorizationStore`** — Stores time-limited authorization grants with automatic expiration.
- **Duktape JS engine** — Evaluates administrator-defined `.rules` JavaScript files to make authorization decisions.

### Client Library (`libpolkit-gobject-1`)

Located in `src/polkit/`, this shared library provides the public API for applications that want to check or request authorization.

Key types:
- **`PolkitAuthority`** — Singleton proxy to the authority daemon over D-Bus. Implements `GInitable` and `GAsyncInitable`.
- **`PolkitSubject`** — Interface for process identification (Unix PID/pidfd, session ID, D-Bus bus name).
- **`PolkitIdentity`** — Interface for user/group identification (Unix UID, GID, netgroup).
- **`PolkitAuthorizationResult`** — Encapsulates the result of an authorization check.
- **`PolkitPermission`** — `GPermission` implementation usable with GTK's `GtkLockButton`.
- **`PolkitDetails`** — Key-value metadata bag passed alongside authorization checks.
- **`PolkitActionDescription`** — Describes a registered policy action.

The library communicates with the daemon exclusively via the system D-Bus using GDBus (GLib's native D-Bus implementation).

### Authentication Agent Library (`libpolkit-agent-1`)

Located in `src/polkitagent/`, this library provides the API for implementing graphical or textual authentication agents.

Key types:
- **`PolkitAgentListener`** — Abstract base class. Subclass this to implement a custom authentication agent. The listener registers on the system bus and receives authentication initiation requests from the daemon.
- **`PolkitAgentSession`** — Manages the authentication conversation with the `polkit-agent-helper-1` helper process. Emits signals (`request`, `show-info`, `show-error`, `completed`) for the agent UI to respond to.
- **`PolkitAgentTextListener`** — A simple terminal-based authentication agent implementation.

### Command-Line Tools

Located in `src/programs/`:
- **`pkexec`** — Execute a command as another user (with polkit authorization).
- **`pkcheck`** — Check whether a process is authorized for a given action.
- **`pkaction`** — List and inspect registered policy actions.
- **`pkttyagent`** — A TTY-based authentication agent for headless environments.

---

## D-Bus Integration

polkit uses GDBus (from GIO/GLib) for all D-Bus communication. It does **not** use libdbus directly in the source code.

### Interface Definitions

D-Bus introspection XML files live in `data/`:
- `org.freedesktop.PolicyKit1.Authority.xml` — The main authority interface with methods like `CheckAuthorization`, `RegisterAuthenticationAgent`, `EnumerateActions`.
- `org.freedesktop.PolicyKit1.AuthenticationAgent.xml` — The interface that authentication agents export, with the `BeginAuthentication` and `CancelAuthentication` methods.

**Note:** These XML files serve as documentation/specification. No code is generated from them at build time. Instead, introspection XML is embedded as C string literals in the source and parsed at runtime with `g_dbus_node_info_new_for_xml()` (see `server_introspection_data` in `polkitbackendauthority.c` and `auth_agent_introspection_data` in `polkitagentlistener.c`).

### Bus Policy

`data/org.freedesktop.PolicyKit1.conf.in` defines the D-Bus security policy, restricting who may own the bus name and who may call specific methods.

### D-Bus Activation

`data/org.freedesktop.PolicyKit1.service.in` enables D-Bus system bus activation of `polkitd`.

---

## GLib / GObject Usage

The entire codebase is built on GLib and the GObject type system.

### GObject Patterns

- **Type macros:** All types use standard GObject cast/check macros (`POLKIT_TYPE_*`, `POLKIT_IS_*`, etc.)
- **Type registration:** `G_DEFINE_TYPE`, `G_DEFINE_TYPE_WITH_CODE`, `G_DEFINE_TYPE_WITH_PRIVATE`, `G_DEFINE_ABSTRACT_TYPE`
- **Interface implementation:** `G_IMPLEMENT_INTERFACE` within `G_DEFINE_TYPE_WITH_CODE`
- **Properties:** Standard `GObject` property system with `PROP_*` enums, `g_object_class_install_property()`, and override of `get_property`/`set_property`
- **Signals:** `g_signal_new()` with `g_cclosure_marshal_*` marshallers (and generated marshallers in `polkitagentmarshal.list`)
- **Initialization:** `GInitable` / `GAsyncInitable` interfaces for objects requiring I/O during construction (e.g., `PolkitAuthority`)

### GLib Async Patterns

The codebase uses the GLib asynchronous method pattern pervasively:

```c
void     polkit_subject_exists        (PolkitSubject       *subject,
                                       GCancellable        *cancellable,
                                       GAsyncReadyCallback  callback,
                                       gpointer             user_data);
gboolean polkit_subject_exists_finish (PolkitSubject       *subject,
                                       GAsyncResult        *res,
                                       GError             **error);
gboolean polkit_subject_exists_sync   (PolkitSubject       *subject,
                                       GCancellable        *cancellable,
                                       GError             **error);
```

Key patterns:
- Each async operation has a `_finish()` counterpart and usually a `_sync()` convenience wrapper
- `GCancellable` is threaded through all cancellable operations
- `GError**` as the last parameter for fallible functions (always nullable by caller)
- `GSimpleAsyncResult` is used throughout (no `GTask` usage in the codebase)
- Sync wrappers use a private `GMainLoop` + callback to block on the async result

### GLib Main Loop

- The daemon runs a `GMainLoop` as its event loop
- Signal handlers are attached via `g_unix_signal_add()` for `SIGINT`, `SIGTERM`, `SIGHUP`
- D-Bus name ownership uses `g_bus_own_name()` with callbacks
- Session monitoring uses a custom `GSource` wrapping `sd_login_monitor`'s pollfd

### GLib Utilities Used Throughout

- `GKeyFile` for INI-style configuration parsing
- `GOptionContext` for command-line argument parsing
- `g_spawn_*` / `posix_spawn` for child process management
- `GFileMonitor` for watching rules directory changes
- `GHashTable`, `GList` for data structures
- `g_autofree`, `g_autoptr` in newer code sections
- `G_DEFINE_AUTOPTR_CLEANUP_FUNC` for autoptr support (e.g., in `polkitagenttypes.h`)

---

## PAM Integration

polkit supports multiple authentication frameworks, selected at build time via the `authfw` meson option: `pam` (default), `shadow`, or `bsdauth`.

The PAM-specific code lives in:
- `src/polkitagent/polkitagenthelper-pam.c` — The `polkit-agent-helper-1` binary (PAM variant). This is a small setuid-root (or socket-activated) helper that:
  1. Receives a username and authentication cookie
  2. Opens a PAM session via `pam_start()` with a custom conversation function
  3. Calls `pam_authenticate()` and `pam_acct_mgmt()`
  4. On success, calls back to the polkit daemon via `polkit_authority_authentication_agent_response_sync()`

- `data/polkit-1.in` / `data/polkit-1.debian` — PAM configuration files (distribution-specific, templated from `meson_options.txt` settings)

The conversation between the authentication agent UI and the helper happens via stdout/stdin pipe (or Unix socket when socket-activated), with a simple line-based protocol (type + escaped value pairs).

---

## systemd Integration

polkit integrates with systemd in several ways:

### Service Management

- `data/polkit.service.in` — systemd service unit for `polkitd` (Type=notify-reload, extensively sandboxed)
- `data/polkit-agent-helper@.service.in` — Template unit for socket-activated authentication helper instances
- `data/polkit-agent-helper.socket` — Socket unit listening on `/run/polkit/agent-helper.socket`

### sd-notify Protocol

The daemon uses `sd_notify()` for:
- `READY=1` — Signals readiness after D-Bus name acquisition
- `RELOADING=1` + `MONOTONIC_USEC=...` — Signals reload-in-progress on `SIGHUP` (compatible with `Type=notify-reload`)
- `STOPPING=1` — Signals graceful shutdown

### Session Tracking (systemd-logind)

`src/polkitbackend/polkitbackendsessionmonitor-systemd.c` uses `libsystemd`'s login APIs:
- `sd_login_monitor_new()` — Creates a monitor for login session changes
- `sd_uid_get_display()` — Resolves a UID's graphical session
- `sd_session_get_uid()`, `sd_session_is_active()`, `sd_session_is_remote()` — Query session properties
- `sd_pidfd_get_session()` / `sd_pid_get_session()` — Map processes to sessions

The monitor is integrated into the GLib main loop via a custom `GSource` that wraps the `sd_login_monitor`'s file descriptor.

### sysusers and tmpfiles

- `data/polkit.conf.in` — sysusers.d configuration for creating the `polkitd` system user
- `data/polkit-tmpfiles.conf.in` — tmpfiles.d configuration for runtime directories

---

## Meson Build System

The project uses Meson (>= 1.4.0) with C99 as the language standard.

### Top-level `meson.build`

Configures project metadata, dependency detection, feature flags, and includes subdirectories. Key dependencies:
- `glib-2.0`, `gobject-2.0`, `gio-2.0`, `gio-unix-2.0` (>= 2.44)
- `duktape` (>= 2.2.0) — JavaScript engine for rules evaluation
- `expat` — XML parsing for action definitions
- `libsystemd` or `libelogind` — Session tracking
- `pam` / `crypt` — Authentication framework
- `dbus-1` (pkg-config only, for directory paths)

### Build Options (`meson_options.txt`)

| Option | Default | Description |
|--------|---------|-------------|
| `session_tracking` | `logind` | Session tracking backend (logind/elogind/ConsoleKit) |
| `authfw` | `pam` | Authentication framework (pam/shadow/bsdauth) |
| `libs-only` | `false` | Only build libraries, skip daemon |
| `polkitd_user` | `polkitd` | System user for daemon |
| `privileged_group` | auto | Administrative group (wheel/sudo) |
| `introspection` | `true` | Generate GObject Introspection data |
| `gtk_doc` | `false` | Build API documentation |
| `man` | `false` | Build man pages |
| `tests` | `false` | Build test suite |
| `examples` | `false` | Build example programs |
| `gettext` | `false` | Enable translations |

### Build Artifacts

| Target | Type | Location |
|--------|------|----------|
| `libpolkit-gobject-1.so` | Shared library | `src/polkit/` |
| `libpolkit-agent-1.so` | Shared library | `src/polkitagent/` |
| `libpolkit-backend-1` | Static library | `src/polkitbackend/` |
| `polkitd` | Executable (daemon) | `src/polkitbackend/` → installed to `lib/polkit-1/` |
| `polkit-agent-helper-1` | Executable (helper) | `src/polkitagent/` → installed to `lib/polkit-1/` |
| `pkexec` | Executable | `src/programs/` |
| `pkcheck` | Executable | `src/programs/` |
| `pkaction` | Executable | `src/programs/` |
| `pkttyagent` | Executable | `src/programs/` |

### GObject Introspection & pkg-config

- GIR files are generated for both `Polkit-1.0` and `PolkitAgent-1.0` namespaces via `gnome.generate_gir()`
- pkg-config files: `polkit-gobject-1.pc` and `polkit-agent-1.pc`


---

## Related Resources

- [polkit man page (polkit(8))](https://www.freedesktop.org/software/polkit/docs/latest/polkit.8.html)
- [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html)
- [GLib/GObject reference](https://docs.gtk.org/glib/)
- [Duktape JavaScript engine](https://duktape.org/)

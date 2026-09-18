# Building polkit

polkit uses Meson with Ninja and a C99 compiler. Run the commands below from the source directory.
Both GCC and Clang are exercised by CI.

## Dependencies

Install the development headers and libraries for your selected configuration:

- Meson >= 1.4.0, Ninja, a C compiler, and pkg-config (or pkgconf).
- GLib, GObject, GIO, and GIO Unix >= 2.44.
- Duktape >= 2.2.0 and Expat for the daemon.
- PAM for the default `-Dauthfw=pam` configuration.
- libsystemd for the default `-Dsession_tracking=logind`, or libelogind for `elogind`.
- GObject Introspection >= 0.6.2, enabled by default; disable with `-Dintrospection=false`.
- Gettext tools for translating policy and service files.

Building API documentation (`-Dgtk_doc=true`) requires gtk-doc and its dependencies.
Building manual pages (`-Dman=true`) requires xsltproc and locally installed DocBook XML/XSL resources.
The build invokes xsltproc with `--nonet`, so its XML catalog must resolve the DocBook resources locally.
D-Bus development metadata is used to discover installation paths when available.
See [Testing](TESTING.md) for Python, dbusmock, and namespace requirements when enabling tests.

The [Fedora Rawhide spec](https://src.fedoraproject.org/rpms/polkit/blob/rawhide/f/polkit.spec)
provides a distribution package list. Its build requirements include `gcc-c++`, `glib2-devel`,
`expat-devel`, `pam-devel`, `gtk-doc`, `gettext-devel`, `gobject-introspection-devel`,
`systemd`, `systemd-devel`, `systemd-rpm-macros`, `dbus-devel`, `pkgconfig(duktape)`, `meson`, and `git`.
Some requirements support RPM packaging; use this checkout's `meson.build` for upstream version requirements.

For e.g. Fedora, the dependency setup used by [CI](../.github/workflows/ci.yml) is:

```bash
sudo dnf install -y dnf-plugins-core python3-dbusmock clang compiler-rt libasan libubsan
sudo dnf builddep -y polkit
```

`dnf builddep` uses the package metadata from your enabled repositories, which can differ from Rawhide
or this checkout. Clang and the sanitizer libraries support the additional CI configurations.
The CI workflow also contains the Alpine dependency setup for elogind builds.

## Configure and Compile

For a default build:

```bash
meson setup builddir
meson compile -C builddir
```

The defaults include `--buildtype=debugoptimized`, `--prefix=/usr`, PAM, logind, and introspection.
Tests, examples, API documentation, and manual pages are disabled by default.

For a development build with tests enabled:

```bash
meson setup builddir -Dtests=true
meson compile -C builddir
```

These setup examples are alternatives for a new build directory. To inspect or change an existing one:

```bash
meson configure builddir
meson configure builddir -Dtests=true
meson compile -C builddir
```

See [Testing](TESTING.md#running) for commands to run the test suite.
Project-specific options are defined in [meson_options.txt](../meson_options.txt).
The [architecture guide](ARCHITECTURE.md#meson-build-system) describes the build structure and targets.

## Fedora Package Configuration

The Rawhide spec configures PAM and logind, enables API documentation, introspection, and manual pages,
and disables examples and tests. Its `%meson` and `%meson_build` steps correspond to setup and compilation,
with distribution paths and compiler flags supplied by RPM macros.
To use the same project options in a separate build directory:

```bash
meson setup build-fedora \
  -Dauthfw=pam -Dsession_tracking=logind \
  -Dgtk_doc=true -Dintrospection=true -Dman=true \
  -Dexamples=false -Dtests=false
meson compile -C build-fedora
```

This reproduces the project option selection; building the RPM also applies Fedora's patches and packaging rules.

## Reproduce CI Builds

[ci.sh](../.github/workflows/ci.sh) takes a phase and a session tracking backend.
After installing the CI dependencies, run one phase from a checkout without an existing `build` directory:

```bash
.github/workflows/ci.sh GCC logind
```

Use `elogind` as the second argument on a system configured with that backend.
All phases enable PAM, examples, API documentation, introspection, and tests.

| Phase | Actions |
|-------|---------|
| `GCC` / `CLANG` | Build with manual pages and fortification, run unit tests, and stage installation in `install-test/`. |
| `BUILD_GCC` / `BUILD_CLANG` | Build with warnings treated as errors at optimization levels 0, 3, and s, then with `b_ndebug=true`; delete `build/` after each configuration. These phases compile tests but do not run them. |
| `GCC_ASAN_UBSAN` / `CLANG_ASAN_UBSAN` | Build and run tests with AddressSanitizer and UndefinedBehaviorSanitizer at optimization level 1; disable manual pages and `b_lundef`. |

Clang phases set `CC=clang` and `CXX=clang++`; GCC phases use the default compiler environment.
The script configures sanitizer runtime options itself.
The workflow selects a subset of these phases for each distribution.

## Installation

To stage an installation for inspection or packaging, as CI does:

```bash
DESTDIR="$PWD/install-test" meson install -C builddir
```

`DESTDIR` places files under a staging directory while preserving the configured installation paths.
An unprivileged staged install reports ownership and setuid permissions that must be set during deployment.

To install onto the system using the configured prefix (default `/usr`):

```bash
sudo meson install -C builddir
```

A system installation also needs the configured `polkitd` service account, appropriate PAM configuration,
and D-Bus/service integration. The Fedora spec handles distribution-specific installation and packaging;
consult it when preparing a Fedora package.

## Troubleshooting

- **Missing dependency:** Install its development package and check `builddir/meson-logs/meson-log.txt`.
  Runtime libraries alone may not supply the required headers or pkg-config metadata.
- **Documentation generation fails:** Check the gtk-doc, xsltproc, and DocBook dependencies,
  or disable optional documentation with `-Dgtk_doc=false -Dman=false` for a local build.
- **Changing compiler:** Use a new build directory, for example `CC=clang meson setup build-clang`.
- **Tests skip or fail during isolation setup:** Follow the Python and namespace requirements in
  [Testing](TESTING.md). The CI workflow uses privileged containers to support its test environment.

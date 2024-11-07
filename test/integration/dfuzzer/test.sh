#!/bin/bash
# vi: set sw=4 ts=4 et tw=110:
# shellcheck disable=SC2016
#
# FIXME: this test can be _drastically_ simplified once we can run a dedicated sanitizer job, see
#        https://github.com/packit/packit-service/issues/2610

set -eux
set -o pipefail

# shellcheck source=test/integration/util.sh
. "$(dirname "$0")/../util.sh"

export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2:handle_ioctl=1:print_cmdline=1:disable_coredump=0:use_madv_dontdump=1
export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
# FIXME: There' a bug in meson where it overrides UBSAN_OPTIONS when MSAN_OPTIONS is not set, see
#        https://github.com/mesonbuild/meson/pull/13001. Drop this once v1.4.1 is widespread enough
export MSAN_OPTIONS=foo
export CC="${CC:-clang}"

# shellcheck disable=SC2317
at_exit() {
    set +ex

    # Let's do some cleanup and export logs if necessary

    # Collect potential coredumps
    coredumpctl_collect
    container_destroy

    if [[ -n "${TMT_TEST_DATA:-}" && -n "${BUILD_DIR:-}" ]]; then
        cp -r "$BUILD_DIR/meson-logs" "$TMT_TEST_DATA/"
    fi
}

trap at_exit EXIT

export BUILD_DIR="$PWD/build-san"

# Make sure the coredump collecting machinery is working
coredumpctl_init

: "=== Prepare polkit's source tree ==="
# The integration test suite runs without access to the source tree it was built from. If we need the source
# tree (most likely to rebuild polkit) we need to do a little dance to determine the correct references.
if [[ -n "${PACKIT_TARGET_URL:-}" ]]; then
    # If we're running in Packit's context, use the set of provided environment variables to checkout the
    # correct branch (and possibly rebase it on top of the latest source base branch so we always test the
    # latest revision possible).
    git clone "$PACKIT_TARGET_URL" polkit
    cd polkit
    git checkout "$PACKIT_TARGET_BRANCH"
    # If we're invoked from a pull request context, rebase on top of the latest source base branch.
    if [[ -n "${PACKIT_SOURCE_URL:-}" ]]; then
        git remote add pr "${PACKIT_SOURCE_URL:?}"
        git fetch pr "${PACKIT_SOURCE_BRANCH:?}"
        git merge "pr/$PACKIT_SOURCE_BRANCH"
    fi
    git log --oneline -5
elif [[ -n "${POLKIT_TREE:-}" ]]; then
    # Useful for quick local debugging when running this script directly, e.g. running
    #
    #   # TMT_TEST_DATA=$PWD/logs POLKIT_TREE=$PWD test/integration/fuzz/sanitizers/test.sh
    #
    # from the polkit repo root.
    cd "${POLKIT_TREE:?}"
else
    # If we're running outside of Packit's context, pull the latest polkit upstream.
    git clone https://github.com/polkit-org/polkit polkit
    cd polkit
    git log --oneline -5
fi

: "=== Build polkit with sanitizers ==="
MESON_OPTIONS=()

if [[ "$CC" == clang ]]; then
    # See https://github.com/mesonbuild/meson/issues/764 for details
    MESON_OPTIONS+=(-Db_lundef=false)
fi

rm -rf "$BUILD_DIR"
# FIXME:
#   - drop -Wno-deprecated-declarations once it's not needed
#   - generating introspection is currently FUBAR when building with clang + ASan,
#     but we shouldn't need it here anyway (see https://github.com/mesonbuild/meson/issues/13211)
meson setup "$BUILD_DIR" \
    --werror \
    -Dintrospection=false \
    -Dsession_tracking=logind \
    -Dgettext=true \
    -Dtests=true \
    -Db_sanitize=address,undefined \
    -Dc_args="-Wno-deprecated-declarations" \
    -Dcpp_args="-Wno-deprecated-declarations" \
    "${MESON_OPTIONS[@]}"
ninja -C "$BUILD_DIR"
meson test -C "$BUILD_DIR" --print-errorlogs

: "=== Run dfuzzer against polkit running under sanitizers ==="
container_prepare

# Install our custom-built polkit into the container's overlay
DESTDIR="$CONTAINER_OVERLAY" ninja -C "$BUILD_DIR" install
# Tweak the polkit.service to make it compatible with sanitizers
mkdir -p "$CONTAINER_OVERLAY/etc/systemd/system/polkit.service.d/"
cat >"$CONTAINER_OVERLAY/etc/systemd/system/polkit.service.d/sanitizer-env.conf" <<EOF
[Service]
# Pass ASAN_OPTIONS and UBSAN_OPTIONS to the polkit service in the container
Environment=ASAN_OPTIONS=$ASAN_OPTIONS
Environment=UBSAN_OPTIONS=$UBSAN_OPTIONS
# Get rid of any existing seccomp filters to allow sanitizers do their work
SystemCallFilter=
# Get rid of --no-debug (since sanitizers log their findings to stderr), and let polkit be as verbose as
# possible
ExecStart=
ExecStart=/usr/lib/polkit-1/polkitd --log-level=debug
EOF

check_journal_for_sanitizer_errors() {
    if journalctl -q -D "/var/log/journal/${CONTAINER_MACHINE_ID:?}" --grep "SUMMARY:.+Sanitizer"; then
        # Dump all messages recorded for the polkit.service, as that's usually where the stack trace ends
        # up. If that's not the case, the full container journal is exported on test exit anyway, so we'll
        # still have everything we need to debug the fail further.
        journalctl -q -D "/var/log/journal/${CONTAINER_MACHINE_ID:?}" -o short-monotonic --no-hostname -u polkit.service --no-pager
        exit 1
    fi
}

run_and_check() {
    local run=(container_run)
    local ec=0

    if [[ "$1" == "--unpriv" ]]; then
        run=(container_run_user testuser)
        shift
    fi

    # Run the passed command in the container
    "${run[@]}" "$@" || ec=$?
    # Check for potential stack traces from sanitizers
    check_journal_for_sanitizer_errors
    # Check if polkit is still running
    "${run[@]}" systemctl status --full --no-pager polkit.service

    return $ec
}

# Start the container and wait until it's fully booted up
container_start
container_run pkexec --version
container_run systemctl start polkit.service
container_run systemctl --no-pager status polkit.service
# Make _extra_ sure we're running the sanitized polkit with the correct environment
#
# Note: the check is not particularly nice, as libasan can be linked either statically or dynamically, so we
# can't just check ldd's output. Another option is using nm/objdump to check for ASan-specific functions, but
# that's also error prone. Instead, let's call each binary with ASan's "help" option, which produces output
# only if the target binary is built with (hopefully working) ASan.
container_run bash -xec 'ASAN_OPTIONS=help=1 /proc/$(systemctl show -P MainPID polkit.service)/exe -h 2>&1 >/dev/null | grep -q AddressSanitizer'
container_run systemctl show -p Environment polkit.service | grep -q ASAN_OPTIONS

# Now we should have a container ready for our shenanigans

# Fuzz polkit's own interface
run_and_check dfuzzer -v -n org.freedesktop.PolicyKit1
run_and_check --unpriv dfuzzer -v -n org.freedesktop.PolicyKit1

# Shut down the container and check for any sanitizer errors, since some of the errors can be detected only
# after we start shutting things down.
container_stop
check_journal_for_sanitizer_errors
# Also, check if polit didn't fail during the lifetime of the container
(! journalctl -q -D "/var/log/journal/$CONTAINER_MACHINE_ID" _PID=1 --grep "polkit.service.*Failed with result")

exit 0

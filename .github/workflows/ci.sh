#!/bin/bash
set -eux
set -o pipefail

# TODO
#   - enable --werror
#       - currently there's a lot of warnings which need to be taken care of first
#   - re-enable test-polkitbackendjsauthority
#       - mocklibc overrides LD_PRELOAD, causing ASan to report false positives
#         (with asan_verify_no_link=0)
#   - re-enable unit tests built with ASan + sanitizers
#       - currently polkit fails to build with clang >= 17 completely, and
#         with older clang it needs to be built with -shared-libasan, which
#         requires another set of tweaks to the environment

PHASE="${1:?}"
COMMON_BUILD_OPTS=(
    -Dauthfw=pam
    -Dexamples=true
    -Dgtk_doc=true
    -Dintrospection=true
    -Dsession_tracking=libsystemd-login
    -Dtests=true
)

if [[ "$PHASE" =~ ^CLANG_ ]]; then
    export CC=clang
    export CXX=clang++
fi

case "$PHASE" in
    BUILD_GCC|BUILD_CLANG)
        # Build test with various levels of optimization and other flags affecting the build

        BUILD_TEST_FLAGS=(
            --optimization=0
            --optimization=3
            --optimization=s
            -Db_ndebug=true
        )

        for opt in "${BUILD_TEST_FLAGS[@]}"; do
            meson setup build \
                -Dman=true \
                -Dcpp_args="-D_FORTIFY_SOURCE=2" \
                "${COMMON_BUILD_OPTS[@]}" \
                "$opt"
            meson compile -C build -v
            rm -rf build
         done
         ;;

    GCC|CLANG)
        # Build + unit tests

        meson setup build \
            -Dman=true \
            -Dcpp_args="-D_FORTIFY_SOURCE=2" \
            "${COMMON_BUILD_OPTS[@]}"

        meson compile -C build -v
        meson test -C build --print-errorlogs
        DESTDIR="$PWD/install-test" meson install -C build
        ;;

    GCC_ASAN_UBSAN|CLANG_ASAN_UBSAN)
        # Build + unit tests with ASan and UBSan

        meson setup build \
            -Dman=false \
            -Db_sanitize=address,undefined \
            --optimization=1 \
            -Db_lundef=false \
            "${COMMON_BUILD_OPTS[@]}"

        # Note: we need to set verify_asan_link_order=0 as polkit LD_PRELOADs libmocklibc in unit tests
        export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:verify_asan_link_order=0
        export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1

        meson compile -C build -v
        meson test -C build --print-errorlogs
        ;;
    *)
        echo >&2 "Unknown phase '$PHASE'"
        exit 1
esac

#!/bin/bash

set -eux
set -o pipefail

EXPECT_SCRIPTS="$PWD/expect"
TEST_USER="polkit-testuser"
TEST_USER_PASSWORD="hello-world-$SRANDOM" # notsecret
TMP_DIR="$(mktemp -d)"

at_exit() {
    set +e

    : "Cleanup"
    userdel -rf "$TEST_USER"
    systemctl restart polkit
    rm -rf "$TMP_DIR"
    rm -f /etc/polkit-1/rules.d/00-test.rules
}

trap at_exit EXIT

: "Setup"
useradd "$TEST_USER"
echo "$TEST_USER_PASSWORD" | passwd --stdin "$TEST_USER"
# We need the Expect scripts to be somewhere accessible to the $TEST_USER
cp -r "$EXPECT_SCRIPTS"/* "$TMP_DIR/"
chown -R "$TEST_USER" "$TMP_DIR"
# Temporarily allow $TEST_USER to gain root privileges
cat >/etc/polkit-1/rules.d/00-test.rules <<EOF
polkit.addAdminRule(function(action, subject) {
    return ["unix-user:$TEST_USER"];
});
EOF

# This a really ugly hack for a particularly annoying Expect's behavior - it closes
# stdout when it gets EOF from stdin, which happens very quickly in CIs where stdin
# is usually closed. The behavior in such case can be reproduced with:
#
#   $ true | setsid --wait pkexec echo hello | cat
#
# To get around this the easiest way possible (at least known to me ATTOW) let's
# redirect /dev/zero to stdin, which keeps it open and makes Expect (and spawned processes)
# behave as expected.
exec 0</dev/zero

: "Sanity checks"
pkexec --help
pkexec --version

: "Basic auth"
# With a valid password
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    bash -xec 'echo "I am now user $(id -un) with UID $(id -u)"' | tee "$TMP_DIR/basic.log"
grep -q "AUTHENTICATION COMPLETE" "$TMP_DIR/basic.log"
grep -q "I am now user root with UID 0" "$TMP_DIR/basic.log"
# With an invalid password
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "nope" \
    bash -xec 'echo "I am now user $(id -un) with UID $(id -u)"' | tee "$TMP_DIR/basic.log" && ec=0 || ec=$?
# pkexec returns 127 when the authorization fails
[[ "$ec" -eq 127 ]]
grep -q "AUTHENTICATION FAILED" "$TMP_DIR/basic.log"
grep -q "Not authorized" "$TMP_DIR/basic.log"
(! grep -q "I am now user root with UID 0" "$TMP_DIR/basic.log")
rm -f "$TMP_DIR/basic.log"

: "Basic auth with --user"
# With a valid password
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    --user "$TEST_USER" bash -xec 'echo "I am now user $(id -un) with UID $(id -u)"' | tee "$TMP_DIR/basic-user.log"
grep -q "AUTHENTICATION COMPLETE" "$TMP_DIR/basic-user.log"
grep -q "I am now user $TEST_USER with UID $(id -u "$TEST_USER")" "$TMP_DIR/basic-user.log"
# With an invalid password
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "nope" \
    --user "$TEST_USER" bash -xec 'echo "I am now user $(id -un) with UID $(id -u)"' | tee "$TMP_DIR/basic-user.log" && ec=0 || ec=$?
# pkexec returns 127 when the authorization fails
[[ "$ec" -eq 127 ]]
grep -q "AUTHENTICATION FAILED" "$TMP_DIR/basic-user.log"
grep -q "Not authorized" "$TMP_DIR/basic-user.log"
(! grep -q "I am now user $TEST_USER with UID $(id -u "$TEST_USER")" "$TMP_DIR/basic-user.log")
rm -f "$TMP_DIR/basic-user.log"

: "--keep-cwd"
# Default working directory (root)
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    bash -xec 'echo "$(id -nu): current working directory is $(pwd)"' | tee "$TMP_DIR/keep-cwd.log"
grep -q "root: current working directory is /root" "$TMP_DIR/keep-cwd.log"
# Default working directory (user)
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    --user "$TEST_USER" bash -xec 'echo "$(id -nu): current working directory is $(pwd)"' | tee "$TMP_DIR/keep-cwd.log"
grep -q "$TEST_USER: current working directory is /home/$TEST_USER" "$TMP_DIR/keep-cwd.log"
# --keep-cwd (root)
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    --keep-cwd bash -xec 'echo "$(id -nu): current working directory is $(pwd)"' | tee "$TMP_DIR/keep-cwd.log"
grep -q "root: current working directory is $PWD" "$TMP_DIR/keep-cwd.log"
# --keep-cwd (user)
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    --keep-cwd --user "$TEST_USER" bash -xec 'echo "$(id -nu): current working directory is $(pwd)"' | tee "$TMP_DIR/keep-cwd.log"
grep -q "$TEST_USER: current working directory is $PWD" "$TMP_DIR/keep-cwd.log"
rm -f "$TMP_DIR/keep-cwd.log"

: "Environment variables"
FOO=bar \
LANG=C \
LD_PRELOAD="/tmp/$SRANDOM" \
PATH="$PATH:/tmp/nope" \
TERM=linux \
USER=foo \
    sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" env | tee "$TMP_DIR/environment.log"
# Expect outputs <CR><LF> instead of just <LF> which confuses grep's anchor ($), so let's
# strip it to make matching easier
sed -i 's/\r$//g' "$TMP_DIR/environment.log"
# pkexec preserves a very limited subset of env variables (see environment_variables_to_save
# in pkexec's main())
#
# Variables set by pkexec
grep -qE "^HOME=/root$" "$TMP_DIR/environment.log"
grep -qE "^LOGNAME=root$" "$TMP_DIR/environment.log"
grep -qE "^PKEXEC_UID=$(id -u "$TEST_USER")$" "$TMP_DIR/environment.log"
grep -qE "^USER=root$" "$TMP_DIR/environment.log"
# pkexec resets $PATH to a predefined safe list
(! grep -qE "^PATH=.*nope.*$" "$TMP_DIR/environment.log")
# Inherited variables
grep -qE "^LANG=C$" "$TMP_DIR/environment.log"
grep -qE "^TERM=linux$" "$TMP_DIR/environment.log"
# Ignored variables
(! grep -qE "^FOO=" "$TMP_DIR/environment.log")
(! grep -qE "^LD_PRELOAD=" "$TMP_DIR/environment.log")
rm -f "$TMP_DIR/environment.log"

: "Ellipsis in a long command line"
# See: https://github.com/polkit-org/polkit/commit/322c014ccf21db7cd223192fa237178645c492e6
sudo -u "$TEST_USER" expect "$TMP_DIR/basic-auth.exp" "$TEST_USER_PASSWORD" \
    echo $(printf "arg%d; " {0..128}) | tee "$TMP_DIR/long-cmdline.log"
grep -Eq "Authentication is needed to run \`.*/echo arg0; arg1;.* ... .*; arg127; arg128;' as the super user" "$TMP_DIR/long-cmdline.log"
grep -q "AUTHENTICATION COMPLETE" "$TMP_DIR/long-cmdline.log"
rm -f "$TMP_DIR/long-cmdline.log"

: "Don't die with SIGTRAP on EOF in password prompt"
# See https://github.com/polkit-org/polkit/commit/6c9c07981f7ac7e7dfde05fa8210ae4204d31139
sudo -u "$TEST_USER" expect "$TMP_DIR/SIGTRAP-on-EOF.exp" | tee "$TMP_DIR/SIGTRAP-on-EOF.log"
grep -q "AUTHENTICATION FAILED" "$TMP_DIR/SIGTRAP-on-EOF.log"
grep -q "Not authorized" "$TMP_DIR/SIGTRAP-on-EOF.log"
rm -f "$TMP_DIR/SIGTRAP-on-EOF.log"

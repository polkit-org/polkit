#!/bin/bash

set -eux
set -o pipefail

TEST_RULES="$PWD/rules"
TEST_USER="polkit-testuser"

at_exit() {
    set +e

    : "Cleanup"
    userdel -rf "$TEST_USER"
    rm -f /etc/polkit-1/rules.d/99-test.rules
    systemctl reload polkit
}

trap at_exit EXIT

: "Setup"
mkdir -p /run/systemd/system/
useradd "$TEST_USER"
# Close stdin, so we get an instant error (Interactive authentication required) instead of having to deal
# with an interactive authentication prompt
exec 0<&-

: "Allow $TEST_USER to start/restart/stop a simple systemd unit"
# Use `systemctl edit --full ...` in the future
cat >/run/systemd/system/start-restart-stop.service <<EOF
[Service]
Type=oneshot
ExecStart=true
EOF
systemctl daemon-reload
# Copy the test polkit rule in place
cp -fv "$TEST_RULES/start-restart-stop-unit.rules" /etc/polkit-1/rules.d/99-test.rules
systemctl reload polkit
# Following systemctl invocations should not trigger polkit's authentication prompt
sudo -u "$TEST_USER" systemctl start start-restart-stop.service
sudo -u "$TEST_USER" systemctl restart start-restart-stop.service
sudo -u "$TEST_USER" systemctl stop start-restart-stop.service
# But these ones should
(! sudo -u "$TEST_USER" systemctl mask start-restart-stop.service)
(! sudo -u "$TEST_USER" systemctl restart systemd-journald.service)
# Cleanup
rm -f /etc/polkit-1/rules.d/99-test.rules

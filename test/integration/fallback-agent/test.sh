#!/bin/bash

set -eux
set -o pipefail

TEST_USER="polkit-agent-$RANDOM"
USER_CREATED=0
TEST_ACTION="/run/polkit-1/actions/org.freedesktop.PolicyKit1.agent-test.policy"
TMP_DIR="$(mktemp -d)"

at_exit() {
    set +e
    if [[ "$USER_CREATED" -eq 1 ]]; then
        userdel -rf "$TEST_USER"
    fi
    rm -rf "$TMP_DIR" "$TEST_ACTION"
    systemctl restart polkit
}
trap at_exit EXIT

useradd "$TEST_USER"
USER_CREATED=1
cp agent.py "$TMP_DIR/"
chmod -R a+rX "$TMP_DIR"
mkdir -p /run/polkit-1/actions
cat >"$TEST_ACTION" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<policyconfig>
  <action id="org.freedesktop.PolicyKit1.agent-test">
    <description>Test authentication agent selection</description>
    <message>Authentication agent test</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
EOF
systemctl restart polkit

# A system service without PAMName has no login session. Use a fresh user so
# there is no graphical session to fall back to either.
systemd-run --wait --pipe --collect --property=User="$TEST_USER" \
    python3 "$TMP_DIR/agent.py"

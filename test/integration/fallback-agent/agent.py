# SPDX-License-Identifier: LGPL-2.0-or-later

import os
from pathlib import Path

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

ACTION = "org.freedesktop.PolicyKit1.agent-test"
AGENT_INTERFACE = "org.freedesktop.PolicyKit1.AuthenticationAgent"
AGENT_PATH = "/org/freedesktop/PolicyKit1/TestAgent"


class Agent(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self.actions = []

    @dbus.service.method(AGENT_INTERFACE, in_signature="sssa{ss}sa(sa{sv})", out_signature="")
    def BeginAuthentication(self, action, message, icon, details, cookie, identities):
        self.actions.append(str(action))
        # Selecting an agent must not authorize the operation by itself.
        # Deliberately finish without authenticating an identity.


dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus()
authority = dbus.Interface(
    bus.get_object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority"),
    "org.freedesktop.PolicyKit1.Authority",
)
# Field 22 in /proc/PID/stat, after the parenthesized command name.
start_time = int(Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19])
process = ("unix-process", {
    "pid": dbus.UInt32(os.getpid()),
    "start-time": dbus.UInt64(start_time),
    "uid": dbus.Int32(os.getuid()),
})
bus_name = ("system-bus-name", {"name": bus.get_unique_name()})
agent = Agent(bus, AGENT_PATH)


def check(subject, interactive, expected_calls):
    loop = GLib.MainLoop()
    replies = []
    errors = []
    agent.actions.clear()

    def reply(result):
        replies.append(result)
        loop.quit()

    def error(exception):
        errors.append(exception)
        loop.quit()

    authority.CheckAuthorization(
        subject, ACTION, dbus.Dictionary(signature="ss"), dbus.UInt32(interactive), "",
        reply_handler=reply, error_handler=error, timeout=10,
    )
    loop.run()
    assert not errors, errors
    assert len(replies) == 1, replies
    assert not replies[0][0], "Authorized without authentication"
    assert agent.actions == [ACTION] * expected_calls, (subject[0], interactive, agent.actions, expected_calls)


for fallback in (False, True):
    authority.RegisterAuthenticationAgentWithOptions(
        process, "C", AGENT_PATH, {"fallback": dbus.Boolean(fallback)},
    )
    try:
        for subject in (process, bus_name):
            check(subject, False, 0)
            check(subject, True, 1)
            print(f"PASS {subject[0]} fallback={fallback}", flush=True)
    finally:
        authority.UnregisterAuthenticationAgent(process, AGENT_PATH)

for subject in (process, bus_name):
    check(subject, True, 0)
    print(f"PASS {subject[0]} without an agent", flush=True)

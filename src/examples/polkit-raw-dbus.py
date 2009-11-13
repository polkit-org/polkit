#!/usr/bin/env python

# Copyright (C) 2009 Red Hat, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General
# Public License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330,
# Boston, MA 02111-1307, USA.
#
# Author: David Zeuthen <davidz@redhat.com>

# Simple example showing how to access the Authority via D-Bus calls
#

import dbus

bus = dbus.SystemBus()
proxy = bus.get_object('org.freedesktop.PolicyKit1', '/org/freedesktop/PolicyKit1/Authority')
authority = dbus.Interface(proxy, dbus_interface='org.freedesktop.PolicyKit1.Authority')

system_bus_name = bus.get_unique_name()

subject = ('system-bus-name', {'name' : system_bus_name})
action_id = 'org.freedesktop.policykit.exec'
details = {}
flags = 1            # AllowUserInteraction flag
cancellation_id = '' # No cancellation id

result = authority.CheckAuthorization(subject, action_id, details, flags, cancellation_id)

print result

#!/usr/bin/python

import dbus
import time

bus = dbus.Bus(dbus.Bus.TYPE_SYSTEM)
obj = dbus.Interface(bus.get_object("dk.fubar.PolKitTestService", "/"), "dk.fubar.PolKitTestService")

while True:
    print obj.Test()
    time.sleep(1)

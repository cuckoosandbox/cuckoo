#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system, path
from plistlib import readPlist
from lib.core.packages import Package

class App(Package):
    """ OS X application analysys package. """

    def prepare(self):
        # We'll launch an executable file of this .app directly,
        # but we need to know what it is, don't we?
        info = readPlist(path.join(self.target, "Contents", "Info.plist"))
        exe_name = info.get("CFBundleExecutable")
        if not exe_name:
            raise Exception("Could not locate an executable of the app bundle")

        self.target = path.join(self.target, "Contents", "MacOS", exe_name)
        # Make sure that our target is executable
        system("/bin/chmod +x \"%s\"" % self.target)

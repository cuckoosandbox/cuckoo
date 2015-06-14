#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system
from lib.core.packages import Package

class MachO(Package):
    """ Mach-O executable analysys package. """

    def start(self):

        if "method" in self.options:
            method = self.options["method"]
        else: # fallback
            method = "apicalls"

        # Ensure that our target is executable
        system("/bin/chmod +x \"%s\"" % self.target)

        if "dtruss" in method:
            for x in self._start_dtruss():
                yield x
        elif "apicalls" in method:
            for x in self._start_apicalls():
                yield x
        else:
            yield "Invalid analysis method \"%S\" for package \"MachO\"" % method

#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from lib.core.packages import Package

class Bash(Package):
    """ Bash shell script analysys package. """

    def start(self):
        # Some scripts are not executable, so we have to use /bin/bash to
        # invoke them
        self.args = [self.target] + self.args
        self.target = "/bin/bash"

        if "method" in self.options:
            method = self.options["method"]
        else: # fallback to dtruss
            method = "dtruss"

        if "dtruss" in method:
            for x in self._start_dtruss():
                yield x
        else:
            yield "Invalid analysis method \"%S\" for package \"Bash\"" % method

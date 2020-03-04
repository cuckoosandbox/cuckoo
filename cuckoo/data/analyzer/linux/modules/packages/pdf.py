#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system
from lib.core.packages import Package

class Pdf(Package):
    """ Bash shell script analysys package. """

    def prepare(self):
        system("/bin/chmod +x \"%s\"" % self.target)
        self.args = [self.target] + self.args
        self.target = "/usr/bin/xpdf"

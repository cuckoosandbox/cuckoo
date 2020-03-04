#!/usr/bin/env python
# Copyright (C) 2018 phdphuc
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from lib.core.packages import Package

class Python(Package):
    """ Python script analysis package. """

    def prepare(self):
        self.args = [self.target] + self.args
        self.target = "/usr/bin/python"

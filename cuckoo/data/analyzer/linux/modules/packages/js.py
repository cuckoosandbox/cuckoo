#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from lib.core.packages import Package

class Js(Package):
    """ Java script analysys package. """

    def prepare(self):
        self.args = [self.target] + self.args
        self.target = "/usr/bin/node"

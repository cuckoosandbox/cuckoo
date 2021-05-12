#!/usr/bin/env python
# Copyright (C) 2018 phdphuc
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from lib.core.packages import Package

class Jar(Package):
    """Java analysis package."""

    def prepare(self):
        class_path = self.options.get("class")
        if class_path:
            args = ["-cp", self.target, class_path]
        else:
            args = ["-jar", self.target]
        self.args = args + self.args
        self.target = "/usr/bin/java"
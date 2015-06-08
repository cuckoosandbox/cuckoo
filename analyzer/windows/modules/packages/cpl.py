# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class CPL(Package):
    """Control Panel Applet analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "control.exe"),
    ]

    def start(self, path):
        control = self.get_path("control.exe")
        return self.execute(control, args=[path])

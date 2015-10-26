# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class Javascript(Package):
    """Javascript analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        return self.execute(wscript, args=[path])

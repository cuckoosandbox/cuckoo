# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

# Originally proposed by kidrek:
# https://github.com/cuckoobox/cuckoo/pull/136

class VBS(Package):
    """VBS analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        return self.execute(wscript, args=[path])

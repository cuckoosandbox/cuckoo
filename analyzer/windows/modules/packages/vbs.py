# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class VBS(Package):
    """VBS analysis package."""
    PATHS = [
        ("System32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("WScript")
        return self.execute(wscript, args=[path], trigger="file:%s" % path)

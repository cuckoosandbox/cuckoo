# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.api.process import Process

class Shellcode(Package):
    """Shellcode (any x86 executable code) analysis package."""

    def start(self, path):
        p = Process()
        dll = self.options.get("dll")
        p.execute(path="bin/execsc.exe", args=[path], suspended=True)
        p.inject(dll)
        p.resume()
        p.wait()
        return p.pid
